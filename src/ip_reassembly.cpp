#include "flowlens/ip_reassembly.hpp"
#include <algorithm>
#include <sstream>

namespace fl {
namespace {
void put16(std::vector<uint8_t>& bytes, size_t at, size_t value) {
    bytes.at(at) = uint8_t(value >> 8); bytes.at(at + 1) = uint8_t(value);
}
bool firstHeaderComplete(const Packet& p) {
    const auto& f = p.fragment;
    size_t at = f.payloadOffset, end = at + f.payloadLength;
    unsigned next = f.nextHeader;
    for (unsigned steps = 0; next == 0 || next == 43 || next == 60 || next == 51; ++steps) {
        if (steps >= 8 || end - at < 2) return false;
        size_t length = next == 51 ? (size_t(p.bytes[at + 1]) + 2) * 4 : (size_t(p.bytes[at + 1]) + 1) * 8;
        if (length > end - at) return false;
        next = p.bytes[at]; at += length;
    }
    if (next == 44) return false;
    if (next == 6) return end - at >= 20 && (p.bytes[at + 12] >> 4) >= 5 &&
        size_t(p.bytes[at + 12] >> 4) * 4 <= end - at;
    if (next == 17) return end - at >= 8;
    if (next == 58) return end - at >= 4;
    return true;
}
}
void IpReassembler::erase(std::map<std::string, Entry>::iterator it) {
    buffered_ -= it->second.bytes; entries_.erase(it);
}
size_t IpReassembler::pending() const {
    return size_t(std::count_if(entries_.begin(), entries_.end(), [](const auto& e) { return !e.second.blocked; }));
}
void IpReassembler::expire(uint64_t timestampNs) {
    watermark_ = std::max(watermark_, timestampNs);
    for (auto it = entries_.begin(); it != entries_.end();) {
        auto current = it++;
        if (watermark_ - current->second.firstSeen >= limits_.ttlNs) {
            if (!current->second.blocked) ++stats_.expired;
            erase(current);
        }
    }
}
void IpReassembler::finish() {
    stats_.incomplete += pending(); entries_.clear(); buffered_ = 0; watermark_ = 0;
}
void IpReassembler::clear() {
    entries_.clear(); stats_ = {}; buffered_ = 0; watermark_ = 0;
}
void IpReassembler::ingest(Packet& p) {
    expire(p.timestampNs);
    if (!p.fragmented || !p.fragment.present) return; // Atomic IPv6 fragments use ordinary parsing.
    ++stats_.fragments;
    const auto& f = p.fragment;
    std::string key = std::to_string(p.sectionId) + "/" + std::to_string(p.interfaceId) + "/" +
        std::to_string(p.linkType) + "/" + p.source + "/" + p.destination + "/" +
        std::to_string(f.identification) + "/" + std::to_string(p.ipVersion == 4 ? f.nextHeader : 0);
    if (p.linkType == 1 && f.ipOffset >= 14)
        key.append(reinterpret_cast<const char*>(p.bytes.data() + 12), f.ipOffset - 12);
    auto notice = [&](const std::string& status, const std::string& detail) {
        p.reassemblyStatus = status;
        p.info = "IP fragment: " + detail;
        p.fields.push_back({"IP reassembly", detail, 0, 0, 0});
    };
    if (!limits_.maxEntries) { ++stats_.limited; notice("limited", "entry limit is zero"); return; }
    auto found = entries_.find(key);
    if (found == entries_.end()) {
        if (entries_.size() >= limits_.maxEntries) {
            auto oldest = std::min_element(entries_.begin(), entries_.end(),
                [](const auto& a, const auto& b) { return a.second.firstSeen < b.second.firstSeen; });
            if (!oldest->second.blocked) ++stats_.evicted;
            erase(oldest);
        }
        found = entries_.emplace(key, Entry{}).first;
        found->second.firstSeen = watermark_;
    }
    auto& entry = found->second;
    if (entry.blocked) { notice("rejected", "datagram already rejected; waiting for TTL"); return; }
    auto reject = [&](const std::string& detail, bool limited = false) {
        buffered_ -= entry.bytes;
        entry.pieces.clear(); std::vector<uint8_t>().swap(entry.prefix); entry.bytes = 0; entry.blocked = true;
        p.reassembledFrom.clear();
        ++stats_.rejected; if (limited) ++stats_.limited;
        p.warnings.push_back("IP reassembly rejected: " + detail);
        notice(limited ? "limited" : "rejected", detail);
    };
    if (!f.complete || !f.payloadLength || f.payloadOffset > p.bytes.size() ||
        f.payloadLength > p.bytes.size() - f.payloadOffset) { reject("truncated or empty fragment"); return; }
    if (f.more && f.payloadLength % 8) { reject("non-final fragment length is not a multiple of eight"); return; }
    if (f.offset > limits_.maxDatagramBytes || f.payloadLength > limits_.maxDatagramBytes - f.offset) {
        reject("datagram byte limit", true); return;
    }
    if (p.ipVersion == 6 && f.offset == 0 && !firstHeaderComplete(p)) {
        reject("IPv6 first fragment does not contain complete upper-layer headers"); return;
    }
    size_t end = f.offset + f.payloadLength;
    if (entry.hasEnd && (end > entry.total || (f.more && end >= entry.total))) {
        reject("fragment exceeds known final length"); return;
    }
    if (!f.more) {
        if (entry.hasEnd && end != entry.total) { reject("conflicting final lengths"); return; }
        for (const auto& piece : entry.pieces)
            if (piece.first + piece.second.bytes.size() > end ||
                (piece.second.more && piece.first + piece.second.bytes.size() == end)) {
                reject("final length conflicts with earlier fragment"); return;
            }
    }
    const auto first = p.bytes.begin() + f.payloadOffset;
    for (const auto& piece : entry.pieces) {
        size_t pieceEnd = piece.first + piece.second.bytes.size();
        if (f.offset < pieceEnd && end > piece.first) {
            if (f.offset == piece.first && f.payloadLength == piece.second.bytes.size() &&
                f.more == piece.second.more && std::equal(first, first + f.payloadLength, piece.second.bytes.begin())) {
                ++stats_.duplicates; notice("duplicate", "identical fragment ignored"); return;
            }
            ++stats_.overlaps; reject("overlapping fragments; entire datagram discarded"); return;
        }
    }
    size_t prefixLength = f.offset == 0 ? f.payloadOffset - (p.ipVersion == 6 ? 8 : 0) : 0;
    size_t additional = f.payloadLength + prefixLength;
    if (entry.pieces.size() >= limits_.maxPieces || additional > limits_.maxBufferBytes ||
        buffered_ > limits_.maxBufferBytes - additional) { reject("piece/global buffer limit", true); return; }
    if (f.offset == 0) {
        entry.first = f; entry.prefix.assign(p.bytes.begin(), p.bytes.begin() + prefixLength);
    }
    if (!f.more) { entry.hasEnd = true; entry.total = end; }
    entry.pieces.emplace(f.offset, Piece{{first, first + f.payloadLength}, f.more, p.id});
    entry.bytes += additional; buffered_ += additional;
    notice("pending", "waiting for missing fragments");
    if (!entry.hasEnd || entry.prefix.empty()) return;
    size_t covered = 0;
    for (const auto& piece : entry.pieces) {
        if (piece.first != covered) return;
        covered += piece.second.bytes.size();
    }
    if (covered != entry.total) return;
    auto datagram = std::make_shared<Packet>();
    datagram->bytes = entry.prefix;
    for (const auto& piece : entry.pieces) {
        datagram->bytes.insert(datagram->bytes.end(), piece.second.bytes.begin(), piece.second.bytes.end());
        p.reassembledFrom.push_back(piece.second.packetId);
    }
    const auto& header = entry.first;
    size_t networkLength = datagram->bytes.size() - header.ipOffset;
    if ((p.ipVersion == 4 && networkLength > 65535) ||
        (p.ipVersion == 6 && networkLength - 40 > 65535)) { reject("IP protocol length limit", true); return; }
    if (p.ipVersion == 4) {
        put16(datagram->bytes, header.ipOffset + 2, networkLength);
        put16(datagram->bytes, header.ipOffset + 6, 0);
        put16(datagram->bytes, header.ipOffset + 10,
              internetChecksum(datagram->bytes.data() + header.ipOffset, header.headerLength, 0, 10));
    } else {
        datagram->bytes.at(header.previousNextHeader) = header.nextHeader;
        put16(datagram->bytes, header.ipOffset + 4, networkLength - 40);
    }
    datagram->id = p.id; datagram->timestampNs = p.timestampNs; datagram->linkType = p.linkType;
    datagram->interfaceId = p.interfaceId; datagram->sectionId = p.sectionId;
    datagram->originalLength = uint32_t(datagram->bytes.size()); datagram->checksumMode = p.checksumMode;
    parse(*datagram);
    if (datagram->fragmented) { reject("nested fragment headers"); return; }
    p.reassembled = datagram;
    p.protocol = datagram->protocol; p.transport = datagram->transport;
    p.sourcePort = datagram->sourcePort; p.destinationPort = datagram->destinationPort;
    p.sequence = datagram->sequence; p.acknowledgment = datagram->acknowledgment;
    p.tcpFlags = datagram->tcpFlags; p.httpHost = datagram->httpHost;
    p.transportChecksum = datagram->transportChecksum;
    p.warnings.erase(std::remove_if(p.warnings.begin(), p.warnings.end(),
        [](const std::string& warning) { return warning.rfind("IP fragment:", 0) == 0; }), p.warnings.end());
    p.warnings.insert(p.warnings.end(), datagram->warnings.begin(), datagram->warnings.end());
    notice("complete", "reassembled " + std::to_string(entry.pieces.size()) + " fragments / " + datagram->info);
    ++stats_.completed; erase(found);
}
} // namespace fl
