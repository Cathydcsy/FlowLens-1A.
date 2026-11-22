#include "flowlens/packet.hpp"
#include "flowlens/pcap_file.hpp"
#include "flowlens/ip_reassembly.hpp"
#include "flowlens/stream.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <random>
#include <cstdio>
#ifdef _WIN32
#include <winsock2.h>
#endif

namespace {
int checks = 0;
void require(bool value, const char* name) {
    if (!value) throw std::runtime_error(std::string("FAILED: ") + name);
    ++checks; std::cout << "PASS " << name << '\n';
}
std::vector<fl::Packet> read(const std::string& path) {
    std::vector<fl::Packet> packets;
    fl::readPcap(path, [&](fl::Packet&& p) { fl::parse(p); packets.push_back(std::move(p)); return true; });
    return packets;
}
void checksumTests(const std::string& root) {
    using State = fl::ChecksumState;
    const uint8_t vector[] = {0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7};
    require(fl::internetChecksum(vector, sizeof(vector)) == 0x220d, "RFC 1071 checksum vector");
    const uint8_t odd[] = {1, 2, 3};
    require(fl::internetChecksum(odd, 3) == 0xfbfd, "odd checksum length padded with zero");
    require(fl::internetChecksum(nullptr, 0) == 0xffff, "empty checksum has no reads");
    auto original = read(root + "/showcase.pcap");
    require(original[0].ipChecksum.state == State::Verified && original[0].transportChecksum.state == State::Verified,
            "IPv4 header and TCP pseudo-header verified");
    require(original[10].transportChecksum.state == State::Verified, "IPv4 UDP verified");
    require(original[12].transportChecksum.state == State::Verified, "ICMPv4 verified");
    require(original[16].transportChecksum.state == State::Verified && original[16].ipChecksum.state == State::NotAvailable,
            "IPv6 TCP pseudo-header verified without IPv4 checksum");
    require(original[17].transportChecksum.state == State::Verified, "ICMPv6 pseudo-header verified");
    auto p = original[0]; p.bytes.back() ^= 1; fl::parse(p);
    require(p.ipChecksum.state == State::Verified && p.transportChecksum.state == State::Incorrect &&
            !p.warnings.empty() && p.protocol == "TCP", "bad TCP warns without changing decoding");
    p = original[0]; p.bytes[22] ^= 1; fl::parse(p);
    require(p.ipChecksum.state == State::Incorrect && p.transportChecksum.state == State::Verified,
            "bad IPv4 TTL checksum does not invalidate TCP pseudo-header");
    p = original[10]; p.bytes[40] = p.bytes[41] = 0; fl::parse(p);
    require(p.transportChecksum.state == State::NotAvailable && p.warnings.empty(), "IPv4 UDP zero means omitted");
    p = original[16]; p.bytes.pop_back(); fl::parse(p);
    require(p.transportChecksum.state == State::NotAvailable, "truncated datagram is not a checksum error");
    p = original[0]; p.bytes.back() ^= 1; p.checksumMode = fl::ChecksumMode::OffloadPossible; fl::parse(p);
    require(p.transportChecksum.state == State::NotAvailable && p.warnings.empty(), "possible live checksum offload is unverified");
    p.linkType = 0; p.bytes.erase(p.bytes.begin(), p.bytes.begin() + 14); p.bytes.insert(p.bytes.begin(), {2, 0, 0, 0});
    p.originalLength = uint32_t(p.bytes.size()); p.checksumMode = fl::ChecksumMode::Automatic; fl::parse(p);
    require(p.transportChecksum.state == State::NotAvailable, "loopback invalid checksum is unverified");
    p.checksumMode = fl::ChecksumMode::Strict; fl::parse(p);
    require(p.transportChecksum.state == State::Incorrect, "strict checksum mode explicitly overrides offload heuristic");
    auto extensions = read(root + "/ipv6_extensions.pcap");
    require(extensions[0].transportChecksum.state == State::Verified && extensions[1].transportChecksum.state == State::Verified,
            "IPv6 hop options and atomic fragment use upper-layer pseudo-header length");
    p = extensions[0]; p.bytes[68] = p.bytes[69] = 0; fl::parse(p);
    require(p.transportChecksum.state == State::Incorrect, "IPv6 UDP zero checksum rejected");
    fl::parse(p);
    require(std::count(p.warnings.begin(), p.warnings.end(), "UDP checksum incorrect") == 1,
            "checksum warnings reset on reparse");
    require(fl::packetJson(original[0]).find("\"status\":\"verified\"") != std::string::npos,
            "checksum status exported to JSON");
}
void put16(std::vector<uint8_t>& b, size_t at, size_t n) { b.at(at) = uint8_t(n >> 8); b.at(at + 1) = uint8_t(n); }
fl::Packet fragment(const fl::Packet& original, size_t offset, size_t length, bool more,
                    uint32_t id = uint32_t(-1), size_t v6Extra = 0) {
    size_t ip = 0;
    for (const auto& field : original.fields)
        if (field.name == "Internet Protocol Version 4" || field.name == "Internet Protocol Version 6") ip = field.offset;
    size_t header = original.ipVersion == 4 ? (original.bytes[ip] & 15) * 4 : 40 + v6Extra;
    if (id == uint32_t(-1)) id = original.ipVersion == 4 ?
        (uint32_t(original.bytes[ip + 4]) << 8) | original.bytes[ip + 5] : 12345;
    fl::Packet p;
    p.linkType = original.linkType; p.timestampNs = 100; p.id = offset + 1;
    p.bytes.assign(original.bytes.begin(), original.bytes.begin() + ip + header);
    if (original.ipVersion == 4) {
        put16(p.bytes, ip + 2, header + length); put16(p.bytes, ip + 4, id);
        put16(p.bytes, ip + 6, offset / 8 + (more ? 0x2000 : 0));
        put16(p.bytes, ip + 10, fl::internetChecksum(p.bytes.data() + ip, header, 0, 10));
    } else {
        size_t previous = v6Extra ? ip + 40 : ip + 6;
        uint8_t next = p.bytes[previous]; p.bytes[previous] = 44;
        put16(p.bytes, ip + 4, v6Extra + 8 + length);
        p.bytes.insert(p.bytes.end(), {next, 0, uint8_t((offset + more) >> 8), uint8_t(offset + more),
            uint8_t(id >> 24), uint8_t(id >> 16), uint8_t(id >> 8), uint8_t(id)});
    }
    p.bytes.insert(p.bytes.end(), original.bytes.begin() + ip + header + offset,
                   original.bytes.begin() + ip + header + offset + length);
    p.originalLength = uint32_t(p.bytes.size()); fl::parse(p); return p;
}
void fragmentTests(const std::string& root) {
    auto sample = read(root + "/showcase.pcap");
    auto original = sample[21]; size_t length = original.bytes.size() - 34;
    auto first = fragment(original, 0, 24, true), last = fragment(original, 24, length - 24, false);
    const auto wire = last.bytes;
    fl::IpReassembler table;
    table.ingest(last); table.ingest(first);
    require(first.reassembled && first.reassemblyStatus == "complete", "IPv4 final fragment may arrive first");
    require(first.reassembled->bytes == original.bytes && last.bytes == wire, "reconstructed IPv4 equals original; capture bytes unchanged");
    require(first.reassembled->transportChecksum.state == fl::ChecksumState::Verified,
            "transport checksum verified after IP reassembly");
    require(table.stats().completed == 1 && table.pending() == 0 && table.buffered() == 0, "completed IP entry releases all bytes");
    fl::FlowTable flows; flows.ingest(first);
    require(first.flowId != 0 && flows.get(first.flowId)->directions[0].contiguous() ==
        std::vector<uint8_t>(original.bytes.begin() + original.payloadOffset, original.bytes.end()),
        "IP datagram continues into existing TCP stream reconstruction");
    table.clear(); first = fragment(original, 0, 24, true); last = fragment(original, 24, length - 24, false);
    auto duplicate = first; table.ingest(first); table.ingest(duplicate); table.ingest(last);
    require(last.reassembled && table.stats().duplicates == 1, "exact duplicate fragment ignored without inflating data");
    table.clear(); first = fragment(original, 0, 24, true); auto overlap = fragment(original, 16, length - 16, false);
    table.ingest(first); table.ingest(overlap); last = fragment(original, 24, length - 24, false); table.ingest(last);
    require(table.stats().overlaps == 1 && !last.reassembled && table.buffered() == 0,
            "overlap rejects entire datagram and later fragments until TTL");
    table.clear(); first = fragment(original, 0, 23, true); table.ingest(first);
    require(first.reassemblyStatus == "rejected", "non-final payload must be a multiple of eight");
    table.clear(); first = fragment(original, 0, 24, true); first.bytes.pop_back(); fl::parse(first); table.ingest(first);
    require(first.reassemblyStatus == "rejected", "truncated fragment never enters reconstruction");
    fl::IpReassemblyLimits limits; limits.ttlNs = 10;
    fl::IpReassembler timed(limits); first = fragment(original, 0, 24, true); timed.ingest(first); timed.expire(90);
    require(timed.pending() == 1, "backward capture timestamps do not underflow TTL");
    timed.expire(110); require(timed.pending() == 0 && timed.stats().expired == 1, "IP reassembly TTL expires deterministically");
    timed.finish(); first.timestampNs = 1; timed.ingest(first); timed.expire(11);
    require(timed.pending() == 0 && timed.stats().expired == 2, "new capture after finish resets reassembly time watermark");
    limits = {}; limits.maxEntries = 1;
    fl::IpReassembler bounded(limits); first = fragment(original, 0, 24, true); bounded.ingest(first);
    auto other = fragment(original, 0, 24, true, 999); bounded.ingest(other);
    require(bounded.pending() == 1 && bounded.stats().evicted == 1, "IP datagram table entry cap enforced");
    bounded.finish(); require(bounded.stats().incomplete == 1 && bounded.buffered() == 0, "EOF counts and releases incomplete datagrams");
    limits = {}; limits.maxDatagramBytes = 20; fl::IpReassembler bytes(limits); bytes.ingest(first);
    require(bytes.stats().limited == 1 && bytes.buffered() == 0, "per-datagram IP byte cap enforced");
    limits = {}; limits.maxBufferBytes = 64; fl::IpReassembler global(limits); global.ingest(first);
    last = fragment(original, 24, length - 24, false); global.ingest(last);
    require(global.stats().limited == 1 && global.buffered() == 0, "global IP buffer cap enforced");
    limits = {}; limits.maxPieces = 1; fl::IpReassembler pieces(limits); pieces.ingest(first);
    last = fragment(original, 24, length - 24, false); pieces.ingest(last);
    require(pieces.stats().limited == 1, "per-datagram fragment count cap enforced");
    table.clear(); first = fragment(original, 0, 24, true); last = fragment(original, 24, length - 24, false);
    last.interfaceId = 1; table.ingest(first); table.ingest(last);
    require(table.pending() == 2 && !last.reassembled, "fragments from different capture interfaces stay separate");
    for (auto name : {"loopback.pcap", "vlan.pcap"}) {
        auto source = read(root + "/" + name)[0];
        size_t ip = source.linkType == 0 ? 4 : 18;
        size_t size = source.bytes.size() - ip - 20;
        auto a = fragment(source, 0, 16, true), b = fragment(source, 16, size - 16, false);
        table.clear(); table.ingest(a); table.ingest(b);
        require(b.reassembled && b.reassembled->bytes == source.bytes, name);
    }
    auto v6 = sample[16]; size_t v6Length = v6.bytes.size() - 54;
    first = fragment(v6, 0, 24, true); last = fragment(v6, 24, v6Length - 24, false);
    table.clear(); table.ingest(last); table.ingest(first);
    require(first.reassembled && first.reassembled->bytes == v6.bytes && first.protocol == "HTTP",
            "IPv6 reassembly removes fragment header and decodes HTTP");
    first = fragment(v6, 0, 16, true); table.clear(); table.ingest(first);
    require(first.reassemblyStatus == "rejected", "IPv6 first fragment must include upper-layer headers");
    auto atomic = fragment(v6, 0, v6Length, false); table.clear(); table.ingest(atomic);
    require(!atomic.fragmented && atomic.protocol == "HTTP" && table.stats().fragments == 0,
            "IPv6 atomic fragments remain independently decoded");
    v6.bytes.erase(v6.bytes.begin(), v6.bytes.begin() + 14); v6.linkType = 101; v6.originalLength = uint32_t(v6.bytes.size()); fl::parse(v6);
    first = fragment(v6, 0, 24, true); last = fragment(v6, 24, v6Length - 24, false);
    table.clear(); table.ingest(first); table.ingest(last);
    require(last.reassembled && last.reassembled->bytes == v6.bytes, "IPv6 reassembly supports raw IP link type");
    auto extension = read(root + "/ipv6_extensions.pcap")[0]; size_t udpLength = extension.bytes.size() - 62;
    first = fragment(extension, 0, 16, true, 123, 8); last = fragment(extension, 16, udpLength - 16, false, 123, 8);
    table.clear(); table.ingest(last); table.ingest(first);
    require(first.reassembled && first.reassembled->bytes == extension.bytes && first.protocol == "DNS",
            "IPv6 per-fragment extension chain restored before UDP/DNS decoding");
}
void pcapngTests(const std::string& root) {
    auto original = read(root + "/showcase.pcap");
    auto little = read(root + "/plus/pcapng_cases/showcase_little.pcapng");
    auto big = read(root + "/plus/pcapng_cases/showcase_big.pcapng");
    bool equal = little.size() == original.size() && big.size() == original.size();
    for (size_t i = 0; equal && i < original.size(); ++i)
        equal = little[i].bytes == original[i].bytes && big[i].bytes == original[i].bytes &&
            little[i].timestampNs == original[i].timestampNs && big[i].timestampNs == original[i].timestampNs;
    require(equal, "PCAPNG little/big endian preserve every frame and nanosecond timestamp");
    size_t consumed = 0;
    auto summary = fl::readPcap(root + "/plus/pcapng_cases/showcase_little.pcapng", [&](fl::Packet&&) { ++consumed; return false; });
    require(summary.pcapng && consumed == 1 && summary.packets == 1, "PCAPNG callback supports intentional early stop");
    bool rejected = false;
    try { fl::readPcap(root + "/plus/pcapng_cases/showcase_little.pcapng", [](fl::Packet&&) { return true; }, 1); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, "PCAPNG configured packet count limit enforced");
    auto simple = read(root + "/plus/pcapng_cases/simple_packet.pcapng");
    require(simple.size() == 1 && !simple[0].timestampAvailable && simple[0].bytes == original[0].bytes,
            "SPB missing timestamp remains explicitly unavailable");
    rejected = false;
    try { fl::writePcap(root + "/plus/.no-time-export.pcap", simple); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, "classic PCAP export does not invent missing SPB timestamps");
    auto multiple = read(root + "/plus/pcapng_cases/interface_isolation.pcapng");
    fl::FlowTable flows;
    for (auto& p : multiple) flows.ingest(p);
    require(flows.all().size() == 2, "identical TCP tuples on PCAPNG interfaces remain separate");
    summary = fl::readPcap(root + "/plus/pcapng_cases/ancillary_block.pcapng", [](fl::Packet&&) { return true; });
    require(summary.skippedBlocks == 1 && summary.packets == 1, "unused well-formed PCAPNG blocks are counted explicitly");
    std::ifstream input(root + "/plus/pcapng_cases/showcase_little.pcapng", std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
    const std::string scratch = root + "/plus/.pcapng-mutation.pcapng";
    std::mt19937 random(0x503434);
    size_t errors = 0;
    for (int i = 0; i < 512; ++i) {
        auto mutation = bytes;
        size_t at = 4 + random() % (mutation.size() - 4);
        mutation[at] ^= uint8_t(1 + random() % 255);
        if (i % 3 == 0) mutation.resize(4 + random() % (mutation.size() - 4));
        { std::ofstream output(scratch, std::ios::binary); output.write(reinterpret_cast<const char*>(mutation.data()), mutation.size()); }
        try { fl::readPcap(scratch, [](fl::Packet&& p) { fl::parse(p); return true; }); }
        catch (const std::exception&) { ++errors; }
    }
    std::remove(scratch.c_str());
    require(errors > 100, "512 deterministic PCAPNG structure mutations reject safely or decode bounded data");
}
}
int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA ws; WSAStartup(MAKEWORD(2, 2), &ws);
#endif
    try {
        std::string root = argc > 1 ? argv[1] : "samples";
        checksumTests(root);
        fragmentTests(root);
        pcapngTests(root);
        std::cout << "RESULT " << checks << " additional checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
