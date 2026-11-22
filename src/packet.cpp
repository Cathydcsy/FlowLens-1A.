#include "flowlens/packet.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace fl {
namespace {
uint16_t u16(const std::vector<uint8_t>& b, size_t o) {
    return uint16_t((b.at(o) << 8) | b.at(o + 1));
}
uint32_t u32(const std::vector<uint8_t>& b, size_t o) {
    return (uint32_t(u16(b, o)) << 16) | u16(b, o + 2);
}
std::string hex(unsigned v, unsigned w = 4) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setw(w) << std::setfill('0') << v;
    return s.str();
}
std::string mac(const std::vector<uint8_t>& b, size_t o) {
    std::ostringstream s;
    for (size_t i = 0; i < 6; i++) {
        if (i)
            s << ":";
        s << std::hex << std::setw(2) << std::setfill('0') << unsigned(b.at(o + i));
    }
    return s.str();
}
std::string lower(std::string s) {
    for (char& c : s)
        c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
bool httpToken(unsigned char c) {
    return std::isalnum(c) || std::string("!#$%&'*+-.^_`|~").find(char(c)) != std::string::npos;
}
struct Decoder {
    Packet& p;
    const std::vector<uint8_t>& b;
    size_t end;
    size_t ipOffset = 0;
    bool ipComplete = false, routed = false;
    explicit Decoder(Packet& q) : p(q), b(q.bytes), end(b.size()) {}
    void need(size_t o, size_t n) const {
        if (o > end || n > end - o)
            throw std::runtime_error("Truncated or invalid header length");
    }
    void f(std::string n, std::string v, size_t o, size_t l, int d = 1) {
        p.fields.push_back({n, v, o, l, d});
    }
    void group(std::string n, size_t o, size_t l) {
        f(n, "", o, l, 0);
    }
    void checksum(ChecksumResult& result, const std::string& name, size_t at, size_t length,
                  size_t field, uint32_t seed, const std::string& unavailable = "") {
        result.stored = u16(b, field);
        if (!unavailable.empty()) result.reason = unavailable;
        else {
            result.computed = internetChecksum(b.data() + at, length, seed, field - at);
            if (name == "UDP" && result.computed == 0) result.computed = 0xffff;
            bool correct = internetChecksum(b.data() + at, length, seed) == 0 &&
                !(name == "UDP" && p.ipVersion == 6 && result.stored == 0);
            bool loopback = p.linkType == 0 || p.linkType == 108 || p.source.rfind("127.", 0) == 0 ||
                            p.destination.rfind("127.", 0) == 0 || p.source == "::1" || p.destination == "::1";
            bool uncertain = p.checksumMode == ChecksumMode::OffloadPossible ||
                (p.checksumMode == ChecksumMode::Automatic && loopback);
            if (correct) { result.state = ChecksumState::Verified; result.reason = "complete bytes match"; }
            else if (uncertain) result.reason = "capture may precede checksum offload / loopback synthesis";
            else {
                result.state = ChecksumState::Incorrect;
                result.reason = "complete bytes do not match";
                p.warnings.push_back(name + " checksum incorrect");
            }
        }
        f(name + " checksum", hex(result.stored) + " / " + checksumStateName(result.state) +
          " (" + result.reason + ")", field, 2);
    }
    void transportChecksum(size_t at, size_t length, size_t field, const std::string& name,
                           bool complete = true) {
        uint32_t seed = 0;
        if (p.transport != 1) {
            std::array<uint8_t, 40> pseudo{};
            size_t n = p.ipVersion == 4 ? 12 : 40;
            size_t a = p.ipVersion == 4 ? 12 : 8, addresses = p.ipVersion == 4 ? 8 : 32;
            std::copy_n(b.data() + ipOffset + a, addresses, pseudo.data());
            pseudo[n - 1] = p.ipVersion == 4 ? uint8_t(length) : p.transport;
            if (p.ipVersion == 4) {
                pseudo[9] = p.transport; pseudo[10] = uint8_t(length >> 8);
            } else {
                for (int i = 0; i < 4; i++) pseudo[32 + i] = uint8_t(length >> ((3 - i) * 8));
            }
            seed = uint16_t(~internetChecksum(pseudo.data(), n));
        }
        std::string reason;
        if (!ipComplete || !complete) reason = "truncated datagram";
        else if (routed) reason = "source/routing header final destination not resolved";
        else if (p.transport == 17 && p.ipVersion == 4 && u16(b, field) == 0)
            reason = "IPv4 UDP checksum omitted";
        checksum(p.transportChecksum, name, at, length, field, seed, reason);
    }
    std::string dnsName(size_t& pos, size_t base, size_t limit) {
        std::string result;
        size_t at = pos;
        bool jumped = false;
        std::set<size_t> seen;
        for (int step = 0; step < 64; step++) {
            if (at >= limit || !seen.insert(at).second)
                throw std::runtime_error("Invalid DNS name pointer");
            unsigned c = b[at++];
            if (c == 0) {
                if (!jumped)
                    pos = at;
                return result.empty() ? "." : result;
            }
            if ((c & 0xc0) == 0xc0) {
                if (at >= limit)
                    throw std::runtime_error("Truncated DNS pointer");
                size_t target = base + (((c & 63) << 8) | b[at++]);
                if (target >= limit)
                    throw std::runtime_error("DNS pointer out of bounds");
                if (!jumped)
                    pos = at;
                jumped = true;
                at = target;
                continue;
            }
            if ((c & 0xc0) || c > 63 || at + c > limit)
                throw std::runtime_error("Invalid DNS label");
            if (!result.empty())
                result += '.';
            for (unsigned j = 0; j < c; j++) {
                unsigned char ch = b[at++];
                result += char(ch >= 33 && ch <= 126 ? ch : '?');
            }
            if (result.size() > 253)
                throw std::runtime_error("DNS name too long");
            if (!jumped)
                pos = at;
        }
        throw std::runtime_error("DNS pointer recursion limit");
    }
    bool dns(size_t o, size_t length) {
        const size_t saved = p.fields.size();
        try {
            if (length < 12)
                return false;
            size_t lim = o + length;
            need(o, length);
            unsigned flags = u16(b, o + 2), qd = u16(b, o + 4), an = u16(b, o + 6), ns = u16(b, o + 8),
                     ar = u16(b, o + 10);
            if (((flags >> 11) & 15) > 5 || qd > 32 || an + ns + ar > 256 || qd + an + ns + ar == 0)
                return false;
            size_t pos = o + 12;
            group("Domain Name System", o, length);
            f("Transaction ID", hex(u16(b, o)), o, 2);
            f("Flags", hex(flags), o + 2, 2);
            f("Questions", std::to_string(qd), o + 4, 2);
            f("Answers", std::to_string(an), o + 6, 2);
            std::string first, answers;
            for (unsigned i = 0; i < qd; i++) {
                size_t start = pos;
                std::string n = dnsName(pos, o, lim);
                if (pos + 4 > lim)
                    throw std::runtime_error("Truncated DNS question");
                auto type = u16(b, pos);
                auto cls = u16(b, pos + 2);
                pos += 4;
                if (i == 0)
                    first = n;
                f("Query", n + " type=" + std::to_string(type) + " class=" + std::to_string(cls), start,
                  pos - start);
            }
            for (unsigned i = 0; i < an + ns + ar; i++) {
                size_t start = pos;
                std::string n = dnsName(pos, o, lim);
                if (pos + 10 > lim)
                    throw std::runtime_error("Truncated DNS record");
                auto type = u16(b, pos);
                auto ttl = u32(b, pos + 4);
                auto len = u16(b, pos + 8);
                pos += 10;
                if (pos + len > lim)
                    throw std::runtime_error("Truncated DNS RDATA");
                std::string value;
                if (type == 1 && len == 4)
                    value = address(b.data() + pos, 4);
                else if (type == 28 && len == 16)
                    value = address(b.data() + pos, 6);
                else if (type == 5 || type == 2 || type == 12) {
                    size_t q = pos;
                    value = dnsName(q, o, lim);
                    if (q > pos + len)
                        throw std::runtime_error("Invalid DNS RDATA name");
                } else
                    value = "type=" + std::to_string(type) + " bytes=" + std::to_string(len);
                f(i < an ? "Answer" : "Additional record", n + " -> " + value + " TTL=" + std::to_string(ttl),
                  start, pos + len - start);
                if (i < an) {
                    if (!answers.empty())
                        answers += ", ";
                    answers += value;
                }
                pos += len;
            }
            if (pos != lim)
                throw std::runtime_error("Trailing DNS bytes");
            p.protocol = "DNS";
            p.info = std::string(flags & 0x8000 ? "Response " : "Query ") + first +
                     (answers.empty() ? "" : " -> " + answers);
            return true;
        } catch (const std::exception&) {
            p.fields.resize(saved);
            return false;
        }
    }
    void application(size_t o, size_t n) {
        if (!n)
            return;
        std::vector<uint8_t> payload(b.begin() + o, b.begin() + o + n);
        std::string host;
        auto http = identifyHttp(payload, &host);
        if (!http.empty()) {
            p.protocol = "HTTP";
            p.info = http;
            p.httpHost = host;
            group("Hypertext Transfer Protocol", o, n);
            auto stop = std::find(payload.begin(), payload.end(), '\n');
            f("Start line", http, o, size_t(stop - payload.begin()));
            if (!host.empty())
                f("Host", host, o, n);
            f("Message analysis", inspectHttp(payload), o, n);
            return;
        }
        if (p.transport == 17 && dns(o, n))
            return;
        if (p.transport == 6 && (p.sourcePort == 53 || p.destinationPort == 53) && n >= 2 &&
            u16(b, o) == n - 2 && dns(o + 2, n - 2))
            return;
        if (p.transport == 6 && n >= 5 && b[o] >= 20 && b[o] <= 23 && b[o + 1] == 3 && b[o + 2] <= 4 &&
            u16(b, o + 3) <= 18432) {
            p.protocol = "TLS";
            p.info =
                "TLS record type=" + std::to_string(b[o]) + "; encrypted application data is not decoded";
            group("Transport Layer Security", o, n);
            f("Record type", std::to_string(b[o]), o, 1);
            f("Legacy record version", hex(u16(b, o + 1)), o + 1, 2);
            f("Record length", std::to_string(u16(b, o + 3)), o + 3, 2);
        }
    }
    void transport(size_t o) {
        if (p.fragmented) {
            p.warnings.push_back("IP fragment: transport/application decoding deferred until bounded IP reassembly completes");
            p.info = "IP fragment";
            return;
        }
        if (p.transport == 6) {
            p.protocol = "TCP";
            need(o, 20);
            unsigned h = (b[o + 12] >> 4) * 4;
            if (h < 20)
                throw std::runtime_error("TCP data offset is smaller than 20");
            need(o, h);
            p.sourcePort = u16(b, o);
            p.destinationPort = u16(b, o + 2);
            p.sequence = u32(b, o + 4);
            p.acknowledgment = u32(b, o + 8);
            p.tcpFlags = b[o + 13];
            group("Transmission Control Protocol", o, h);
            f("Source port", std::to_string(p.sourcePort), o, 2);
            f("Destination port", std::to_string(p.destinationPort), o + 2, 2);
            f("Sequence number", std::to_string(p.sequence), o + 4, 4);
            f("Acknowledgment", std::to_string(p.acknowledgment), o + 8, 4);
            f("Header length", std::to_string(h), o + 12, 1);
            f("Flags", tcpFlags(p.tcpFlags), o + 13, 1);
            f("Window", std::to_string(u16(b, o + 14)), o + 14, 2);
            transportChecksum(o, end - o, o + 16, "TCP");
            if (h > 20)
                f("Options", std::to_string(h - 20) + " bytes", o + 20, h - 20);
            p.payloadOffset = o + h;
            p.payloadLength = end - p.payloadOffset;
            p.info = std::to_string(p.sourcePort) + " -> " + std::to_string(p.destinationPort) + " [" +
                     tcpFlags(p.tcpFlags) + "] Seq=" + std::to_string(p.sequence) +
                     " Ack=" + std::to_string(p.acknowledgment) + " Len=" + std::to_string(p.payloadLength);
            application(p.payloadOffset, p.payloadLength);
        } else if (p.transport == 17) {
            p.protocol = "UDP";
            need(o, 8);
            unsigned len = u16(b, o + 4);
            if (len < 8)
                throw std::runtime_error("Invalid UDP length");
            if (len > end - o)
                p.warnings.push_back("UDP datagram truncated");
            p.sourcePort = u16(b, o);
            p.destinationPort = u16(b, o + 2);
            group("User Datagram Protocol", o, 8);
            f("Source port", std::to_string(p.sourcePort), o, 2);
            f("Destination port", std::to_string(p.destinationPort), o + 2, 2);
            f("Length", std::to_string(len), o + 4, 2);
            transportChecksum(o, std::min(size_t(len), end - o), o + 6, "UDP", len <= end - o);
            p.payloadOffset = o + 8;
            p.payloadLength = std::min(size_t(len - 8), end - p.payloadOffset);
            p.info = std::to_string(p.sourcePort) + " -> " + std::to_string(p.destinationPort) +
                     " Len=" + std::to_string(p.payloadLength);
            application(p.payloadOffset, p.payloadLength);
        } else if (p.transport == 1 || p.transport == 58) {
            p.protocol = p.transport == 1 ? "ICMP" : "ICMPv6";
            need(o, 4);
            group(p.protocol, o, end - o);
            f("Type", std::to_string(b[o]), o, 1);
            f("Code", std::to_string(b[o + 1]), o + 1, 1);
            transportChecksum(o, end - o, o + 2, p.protocol);
            p.info = "Type=" + std::to_string(b[o]) + " Code=" + std::to_string(b[o + 1]);
            if ((p.transport == 1 && (b[o] == 0 || b[o] == 8)) ||
                (p.transport == 58 && (b[o] == 128 || b[o] == 129))) {
                need(o, 8);
                f("Identifier", std::to_string(u16(b, o + 4)), o + 4, 2);
                f("Sequence", std::to_string(u16(b, o + 6)), o + 6, 2);
                p.info += (b[o] == 8 || b[o] == 128) ? " Echo request" : " Echo reply";
            }
        } else
            p.info = "IP protocol / next header " + std::to_string(p.transport);
    }
    void ip(size_t o, unsigned eth) {
        ipOffset = o;
        if (eth == 0x0800) {
            p.ipVersion = 4;
            p.protocol = "IPv4";
            need(o, 20);
            unsigned h = (b[o] & 15) * 4, total = u16(b, o + 2);
            if (b[o] >> 4 != 4 || h < 20 || total < h)
                throw std::runtime_error("Invalid IPv4 header");
            need(o, h);
            ipComplete = total <= end - o;
            if (total > end - o)
                p.warnings.push_back("IPv4 packet truncated");
            end = std::min(end, o + total);
            p.source = address(b.data() + o + 12, 4);
            p.destination = address(b.data() + o + 16, 4);
            p.transport = b[o + 9];
            unsigned frag = u16(b, o + 6);
            p.fragmented = (frag & 0x3fff) != 0;
            if (p.fragmented) {
                p.fragment = {true, (frag & 0x2000) != 0, ipComplete, u16(b, o + 4),
                              size_t(frag & 0x1fff) * 8, o + h, end - o - h, o, h, 0, p.transport};
            }
            group("Internet Protocol Version 4", o, h);
            f("Version / header length", "4 / " + std::to_string(h), o, 1);
            f("Total length", std::to_string(total), o + 2, 2);
            f("Identification", hex(u16(b, o + 4)), o + 4, 2);
            f("Flags / fragment offset", hex(frag), o + 6, 2);
            f("TTL", std::to_string(b[o + 8]), o + 8, 1);
            f("Protocol", std::to_string(p.transport), o + 9, 1);
            f("Source", p.source, o + 12, 4);
            f("Destination", p.destination, o + 16, 4);
            checksum(p.ipChecksum, "IPv4", o, h, o + 10, 0);
            for (size_t opt = o + 20; opt < o + h;) {
                unsigned type = b[opt];
                if (type == 0) break;
                if (type == 1) { opt++; continue; }
                if (opt + 2 > o + h || b[opt + 1] < 2 || b[opt + 1] > o + h - opt) { routed = true; break; }
                if (type == 131 || type == 137) routed = true;
                opt += b[opt + 1];
            }
            if (h > 20)
                f("Options", std::to_string(h - 20) + " bytes", o + 20, h - 20);
            transport(o + h);
        } else if (eth == 0x86dd) {
            p.ipVersion = 6;
            p.protocol = "IPv6";
            need(o, 40);
            if (b[o] >> 4 != 6)
                throw std::runtime_error("Invalid IPv6 version");
            unsigned len = u16(b, o + 4);
            ipComplete = len <= end - o - 40;
            if (len == 0 && b[o + 6] == 0 && end > o + 40)
                throw std::runtime_error("IPv6 jumbograms are not supported");
            if (len > end - o - 40)
                p.warnings.push_back("IPv6 packet truncated");
            end = std::min(end, o + 40 + len);
            p.source = address(b.data() + o + 8, 6);
            p.destination = address(b.data() + o + 24, 6);
            p.transport = b[o + 6];
            group("Internet Protocol Version 6", o, 40);
            f("Payload length", std::to_string(len), o + 4, 2);
            f("Next header", std::to_string(p.transport), o + 6, 1);
            f("Hop limit", std::to_string(b[o + 7]), o + 7, 1);
            f("Source", p.source, o + 8, 16);
            f("Destination", p.destination, o + 24, 16);
            size_t at = o + 40;
            size_t previousNext = o + 6;
            unsigned steps = 0;
            while (p.transport == 0 || p.transport == 43 || p.transport == 60 || p.transport == 44 ||
                   p.transport == 51) {
                if (++steps > 8)
                    throw std::runtime_error("IPv6 extension chain exceeds limit");
                need(at, 2);
                unsigned old = p.transport, next = b[at];
                size_t h = old == 44 ? 8 : (old == 51 ? (b[at + 1] + 2) * 4 : (b[at + 1] + 1) * 8);
                need(at, h);
                if (old == 43 && h >= 4 && b[at + 3] != 0) routed = true;
                f("Extension header", std::to_string(old) + " -> " + std::to_string(next), at, h);
                if (old == 44) {
                    unsigned fr = u16(b, at + 2);
                    if (b[at + 1] || (fr & 6)) throw std::runtime_error("Invalid IPv6 fragment reserved bits");
                    p.fragment = {true, (fr & 1) != 0, ipComplete, u32(b, at + 4),
                                  size_t(fr & 0xfff8), at + 8, end - at - 8, o, at - o,
                                  previousNext, uint8_t(next)};
                    if (fr & 0xfff9)
                        p.fragmented = true;
                }
                previousNext = at;
                p.transport = uint8_t(next);
                at += h;
                if (p.fragmented)
                    break;
            }
            transport(at);
        } else if (eth == 0x0806) {
            p.protocol = "ARP";
            need(o, 8);
            auto hl = b[o + 4], pl = b[o + 5];
            need(o + 8, 2 * (size_t(hl) + pl));
            group("Address Resolution Protocol", o, 8 + 2 * (size_t(hl) + pl));
            f("Hardware type", std::to_string(u16(b, o)), o, 2);
            f("Protocol type", hex(u16(b, o + 2)), o + 2, 2);
            f("Opcode", std::to_string(u16(b, o + 6)), o + 6, 2);
            if (hl == 6 && pl == 4 && u16(b, o + 2) == 0x0800) {
                p.source = address(b.data() + o + 14, 4);
                p.destination = address(b.data() + o + 24, 4);
                f("Sender MAC", mac(b, o + 8), o + 8, 6);
                f("Sender IP", p.source, o + 14, 4);
                f("Target MAC", mac(b, o + 18), o + 18, 6);
                f("Target IP", p.destination, o + 24, 4);
                p.info = u16(b, o + 6) == 1 ? "Who has " + p.destination + "? Tell " + p.source
                                            : p.source + " is at " + mac(b, o + 8);
            }
        } else {
            p.protocol = "Ethernet";
            p.info = "Unsupported EtherType " + hex(eth);
        }
    }
    void run() {
        group("Frame", 0, b.size());
        f("Captured length", std::to_string(b.size()), 0, b.size());
        f("Original length", std::to_string(p.originalLength), 0, 0);
        f("Link type", std::to_string(p.linkType), 0, 0);
        if (!p.timestampAvailable) f("Timestamp", "not available in this capture block", 0, 0);
        if (p.originalLength > b.size())
            p.warnings.push_back("Capture is shorter than original frame");
        if (p.linkType == 1) {
            need(0, 14);
            group("Ethernet II", 0, 14);
            p.source = mac(b, 6);
            p.destination = mac(b, 0);
            f("Destination MAC", p.destination, 0, 6);
            f("Source MAC", p.source, 6, 6);
            unsigned eth = u16(b, 12);
            size_t at = 14;
            f("EtherType", hex(eth), 12, 2);
            for (int i = 0; (eth == 0x8100 || eth == 0x88a8) && i < 4; i++) {
                need(at, 4);
                f("VLAN ID", std::to_string(u16(b, at) & 4095), at, 2);
                eth = u16(b, at + 2);
                at += 4;
            }
            ip(at, eth);
        } else if (p.linkType == 0 || p.linkType == 108) {
            need(0, 5);
            group("Loopback", 0, 4);
            ip(4, (b[4] >> 4) == 6 ? 0x86dd : 0x0800);
        } else if (p.linkType == 101 || p.linkType == 12 || p.linkType == 228 || p.linkType == 229) {
            need(0, 1);
            ip(0, (b[0] >> 4) == 6 ? 0x86dd : 0x0800);
        } else if (p.linkType == 113) {
            need(0, 16);
            group("Linux cooked capture", 0, 16);
            ip(16, u16(b, 14));
        } else if (p.linkType == 276) {
            need(0, 20);
            group("Linux cooked capture v2", 0, 20);
            ip(20, u16(b, 0));
        } else {
            p.protocol = "Unsupported";
            p.warnings.push_back("Unsupported link type " + std::to_string(p.linkType));
        }
    }
};
} // namespace
std::string address(const uint8_t* data, int family) {
    char out[INET6_ADDRSTRLEN]{};
    if (!inet_ntop(family == 4 ? AF_INET : AF_INET6, const_cast<uint8_t*>(data), out, sizeof(out)))
        return "?";
    return out;
}
std::string endpoint(const std::string& ip, uint16_t port) {
    return (ip.find(':') != std::string::npos ? "[" + ip + "]" : ip) + ":" + std::to_string(port);
}
std::string tcpFlags(uint8_t flags) {
    std::string s;
    const char* names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    for (int i = 0; i < 8; i++)
        if (flags & (1 << i)) {
            if (!s.empty())
                s += ' ';
            s += names[i];
        }
    return s;
}
std::string printable(const std::vector<uint8_t>& bytes) {
    std::string s;
    s.reserve(bytes.size());
    for (uint8_t c : bytes)
        s += char((c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t' ? c : '.');
    return s;
}
std::string identifyHttp(const std::vector<uint8_t>& bytes, std::string* host) {
    if (bytes.size() < 12)
        return {};
    std::string s(bytes.begin(), bytes.end());
    auto e = s.find("\r\n");
    if (e == std::string::npos || e > 8192)
        return {};
    std::string line = s.substr(0, e);
    bool response = line.compare(0, 9, "HTTP/1.1 ") == 0 || line.compare(0, 9, "HTTP/1.0 ") == 0;
    bool valid =
        response && line.size() >= 12 &&
        std::all_of(line.begin() + 9, line.begin() + 12, [](char c) { return c >= '0' && c <= '9'; });
    if (!response) {
        auto space = line.find(' '), last = line.rfind(' ');
        if (space != std::string::npos && space > 0 && space <= 32 && last > space + 1) {
            bool token = std::all_of(line.begin(), line.begin() + space,
                                     [](char c) { return httpToken(static_cast<unsigned char>(c)); });
            auto ver = line.substr(last + 1);
            valid = token && (ver == "HTTP/1.1" || ver == "HTTP/1.0");
        }
    }
    if (!valid)
        return {};
    auto headersEnd = s.find("\r\n\r\n");
    if (headersEnd == std::string::npos)
        return {};
    size_t pos = e + 2;
    while (pos < headersEnd) {
        auto next = s.find("\r\n", pos);
        if (next == std::string::npos)
            return {};
        auto colon = s.find(':', pos);
        if (colon == std::string::npos || colon >= next || colon == pos)
            return {};
        for (size_t i = pos; i < colon; i++)
            if (!httpToken(static_cast<unsigned char>(s[i])))
                return {};
        if (host && lower(s.substr(pos, colon - pos)) == "host") {
            size_t start = colon + 1;
            while (start < next && (s[start] == ' ' || s[start] == '\t'))
                start++;
            *host = s.substr(start, next - start);
        }
        pos = next + 2;
    }
    return line;
}
std::string inspectHttp(const std::vector<uint8_t>& bytes) {
    std::string s(bytes.begin(), bytes.end());
    size_t at = 0, count = 0;
    std::ostringstream result;
    while (at < s.size() && count < 100) {
        std::vector<uint8_t> tail(bytes.begin() + at, bytes.end());
        std::string host;
        auto line = identifyHttp(tail, &host);
        if (line.empty()) {
            result << "Incomplete or unrecognized message at offset " << at;
            break;
        }
        size_t he = s.find("\r\n\r\n", at), body = he + 4, next = body;
        std::string heads = lower(s.substr(at, he - at));
        result << "Message " << ++count << ": " << line;
        if (!host.empty())
            result << " | Host=" << host;
        result << "\n";
        if (heads.find("transfer-encoding: chunked") != std::string::npos) {
            size_t total = 0;
            bool complete = false;
            for (int chunks = 0; chunks < 10000; chunks++) {
                auto ce = s.find("\r\n", next);
                if (ce == std::string::npos)
                    break;
                auto token = s.substr(next, ce - next);
                auto semi = token.find(';');
                if (semi != std::string::npos)
                    token.resize(semi);
                if (token.empty() || token.size() > 8 || !std::all_of(token.begin(), token.end(), [](char c) {
                        return std::isxdigit(static_cast<unsigned char>(c));
                    }))
                    break;
                size_t len = std::stoul(token, nullptr, 16);
                next = ce + 2;
                if (len == 0) {
                    if (s.compare(next, 2, "\r\n") == 0) {
                        next += 2;
                        complete = true;
                    } else {
                        auto end = s.find("\r\n\r\n", next);
                        if (end != std::string::npos) {
                            next = end + 4;
                            complete = true;
                        }
                    }
                    break;
                }
                if (len > s.size() - next || s.size() - next - len < 2 ||
                    s.compare(next + len, 2, "\r\n") != 0)
                    break;
                total += len;
                next += len + 2;
            }
            result << "Chunked body: " << total << " decoded bytes; "
                   << (complete ? "complete" : "incomplete") << "\n";
            if (!complete)
                break;
        } else {
            auto cl = heads.find("\r\ncontent-length:");
            if (cl != std::string::npos) {
                size_t v = cl + 17;
                while (v < heads.size() && heads[v] == ' ')
                    v++;
                auto e = heads.find("\r\n", v);
                if (e == std::string::npos)
                    e = heads.size();
                std::string number = heads.substr(v, e - v);
                if (number.empty() || number.size() > 12 ||
                    !std::all_of(number.begin(), number.end(), [](char c) { return c >= '0' && c <= '9'; })) {
                    result << "Invalid Content-Length\n";
                    break;
                }
                uint64_t length = std::stoull(number);
                if (length > s.size() - body) {
                    result << "Body incomplete: " << s.size() - body << " / " << length << " bytes\n";
                    break;
                }
                next = body + size_t(length);
                result << "Body complete: " << length << " bytes\n";
            } else {
                result << "No explicit body length; body framing depends on response/request context\n";
                break;
            }
        }
        if (next <= at)
            break;
        at = next;
    }
    return result.str();
}
void parse(Packet& p) {
    // 重新解析时不能保留上一次输入留下的派生字段。
    p.fields.clear();
    p.warnings.clear();
    p.source.clear();
    p.destination.clear();
    p.info.clear();
    p.httpHost.clear();
    p.protocol = "Unknown";
    p.sourcePort = p.destinationPort = 0;
    p.ipVersion = p.transport = p.tcpFlags = 0;
    p.sequence = p.acknowledgment = 0;
    p.payloadOffset = p.payloadLength = 0;
    p.fragmented = false;
    p.ipChecksum = {};
    p.transportChecksum = {};
    p.fragment = {};
    p.reassemblyStatus.clear();
    p.reassembled.reset();
    p.reassembledFrom.clear();
    p.flowProcesses.clear();
    try {
        Decoder(p).run();
    } catch (const std::exception& e) {
        p.warnings.push_back(e.what());
        p.info += (p.info.empty() ? "" : " | ") + std::string(e.what());
        p.payloadLength = 0;
    }
}
std::string jsonEscape(const std::string& text, bool preserveUtf8) {
    std::ostringstream o;
    for (unsigned char c : text) {
        switch (c) {
        case '"':
            o << "\\\"";
            break;
        case '\\':
            o << "\\\\";
            break;
        case '\n':
            o << "\\n";
            break;
        case '\r':
            o << "\\r";
            break;
        case '\t':
            o << "\\t";
            break;
        default:
            if (c < 32 || (c >= 127 && !preserveUtf8))
                o << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << unsigned(c);
            else
                o << c;
        }
    }
    return o.str();
}
std::string packetJson(const Packet& p) {
    std::ostringstream o;
    o << "{\"id\":" << p.id << ",\"timestamp_ns\":" << p.timestampNs << ",\"source\":\""
      << jsonEscape(p.source) << "\",\"destination\":\"" << jsonEscape(p.destination)
      << "\",\"source_port\":" << p.sourcePort << ",\"destination_port\":" << p.destinationPort
      << ",\"protocol\":\"" << p.protocol << "\",\"transport\":" << unsigned(p.transport)
      << ",\"ip_version\":" << unsigned(p.ipVersion) << ",\"sequence\":" << p.sequence
      << ",\"acknowledgment\":" << p.acknowledgment << ",\"tcp_flags\":" << unsigned(p.tcpFlags)
      << ",\"length\":" << p.originalLength << ",\"captured_length\":" << p.bytes.size()
      << ",\"flow_id\":" << p.flowId << ",\"pid\":" << p.pid << ",\"info\":\"" << jsonEscape(p.info)
      << "\",\"warnings\":[";
    for (size_t i = 0; i < p.warnings.size(); i++) {
        if (i)
            o << ',';
        o << '"' << jsonEscape(p.warnings[i]) << '"';
    }
    auto checksumJson = [&](const ChecksumResult& result) {
        o << "{\"status\":\"" << checksumStateName(result.state) << "\",\"stored\":" << result.stored
          << ",\"computed\":" << result.computed << ",\"reason\":\"" << jsonEscape(result.reason) << "\"}";
    };
    o << "],\"peer_pid\":" << p.peerPid << ",\"flow_processes\":[";
    bool firstOwner = true;
    for (const auto& owner : p.flowProcesses) {
        if (!firstOwner) o << ',';
        firstOwner = false;
        o << "{\"pid\":" << owner.first << ",\"process\":\"" << jsonEscape(owner.second, true) << "\"}";
    }
    o << "],\"checksums\":{\"ipv4\":";
    checksumJson(p.ipChecksum);
    o << ",\"transport\":";
    checksumJson(p.transportChecksum);
    o << "},\"timestamp_available\":" << (p.timestampAvailable ? "true" : "false")
      << ",\"link_type\":" << p.linkType << ",\"interface_id\":" << p.interfaceId << ",\"section_id\":" << p.sectionId
      << ",\"fragmented\":" << (p.fragmented ? "true" : "false")
      << ",\"reassembly_status\":\"" << jsonEscape(p.reassemblyStatus) << "\"";
    if (p.reassembled) {
        o << ",\"reassembled_from\":[";
        for (size_t i = 0; i < p.reassembledFrom.size(); ++i) { if (i) o << ','; o << p.reassembledFrom[i]; }
        o << "],\"reassembled_datagram\":" << packetJson(*p.reassembled);
    }
    o << "}";
    return o.str();
}
} // namespace fl
