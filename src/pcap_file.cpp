#include "flowlens/pcap_file.hpp"
#include <array>
#include <fstream>
#include <stdexcept>

namespace fl {
PcapSummary readPcapNg(std::istream& input, const std::function<bool(Packet&&)>& consume, size_t maxPackets);
namespace {
uint32_t get(const uint8_t* p, bool little) {
    return little ? uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24)
                  : (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
void put(std::ostream& o, uint32_t n) {
    for (int i = 0; i < 4; i++)
        o.put(char((n >> (i * 8)) & 255));
}
} // namespace
PcapSummary readPcap(const std::string& path, const std::function<bool(Packet&&)>& consume,
                     size_t maxPackets) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("Cannot open PCAP file");
    std::array<uint8_t, 4> prefix{};
    in.read(reinterpret_cast<char*>(prefix.data()), prefix.size());
    if (in.gcount() != 4) throw std::runtime_error("Truncated capture file magic");
    in.seekg(0);
    if (get(prefix.data(), true) == 0x0a0d0d0a) return readPcapNg(in, consume, maxPackets);
    std::array<uint8_t, 24> h{};
    in.read(reinterpret_cast<char*>(h.data()), h.size());
    if (in.gcount() != 24)
        throw std::runtime_error("Truncated PCAP global header");
    uint32_t magic = get(h.data(), true);
    bool little = magic == 0xa1b2c3d4 || magic == 0xa1b23c4d;
    if (!little && magic != 0xd4c3b2a1 && magic != 0x4d3cb2a1)
        throw std::runtime_error("Not a recognized PCAP or PCAPNG file");
    unsigned major = little ? h[4] | (unsigned(h[5]) << 8) : (unsigned(h[4]) << 8) | h[5];
    unsigned minor = little ? h[6] | (unsigned(h[7]) << 8) : (unsigned(h[6]) << 8) | h[7];
    if (major != 2 || minor != 4)
        throw std::runtime_error("Unsupported PCAP version");
    PcapSummary result;
    result.nanoseconds = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
    result.snaplen = get(h.data() + 16, little);
    result.linkType = get(h.data() + 20, little) & 0xffff;
    if (result.snaplen == 0 || result.snaplen > 16 * 1024 * 1024)
        throw std::runtime_error("Invalid PCAP snapshot length");
    std::array<uint8_t, 16> record{};
    while (in.read(reinterpret_cast<char*>(record.data()), record.size()) || in.gcount()) {
        if (in.gcount() != 16)
            throw std::runtime_error("Truncated PCAP record header");
        uint32_t sec = get(record.data(), little), sub = get(record.data() + 4, little),
                 cap = get(record.data() + 8, little), len = get(record.data() + 12, little);
        if (cap > result.snaplen || cap > 16 * 1024 * 1024 || cap > len ||
            sub >= (result.nanoseconds ? 1000000000u : 1000000u))
            throw std::runtime_error("Invalid PCAP record length or timestamp");
        Packet p;
        p.timestampNs = uint64_t(sec) * 1000000000ULL + uint64_t(sub) * (result.nanoseconds ? 1 : 1000);
        p.originalLength = len;
        p.linkType = result.linkType;
        p.bytes.resize(cap);
        p.id = result.packets + 1;
        if (cap) {
            in.read(reinterpret_cast<char*>(p.bytes.data()), cap);
            if (size_t(in.gcount()) != cap)
                throw std::runtime_error("Truncated PCAP record data");
        }
        if (result.packets >= maxPackets)
            throw std::runtime_error("PCAP packet count exceeds configured limit");
        result.packets++;
        if (!consume(std::move(p)))
            break;
    }
    if (in.bad())
        throw std::runtime_error("PCAP input read failed");
    return result;
}
void writePcap(const std::string& path, const std::vector<Packet>& packets, uint32_t linkType) {
    for (const auto& p : packets) {
        if (p.linkType != linkType)
            throw std::runtime_error("A classic PCAP file cannot mix link types");
        if (!p.timestampAvailable) throw std::runtime_error("Classic PCAP requires timestamps; this packet has no timestamp");
    }
    std::ofstream out(path, std::ios::binary);
    if (!out)
        throw std::runtime_error("Cannot create PCAP file");
    put(out, 0xa1b23c4d);
    out.put(2);
    out.put(0);
    out.put(4);
    out.put(0);
    put(out, 0);
    put(out, 0);
    put(out, 16 * 1024 * 1024);
    put(out, linkType);
    for (const auto& p : packets) {
        put(out, uint32_t(p.timestampNs / 1000000000ULL));
        put(out, uint32_t(p.timestampNs % 1000000000ULL));
        put(out, uint32_t(p.bytes.size()));
        put(out, p.originalLength);
        if (!p.bytes.empty())
            out.write(reinterpret_cast<const char*>(p.bytes.data()), p.bytes.size());
    }
    if (!out)
        throw std::runtime_error("PCAP output write failed");
}
} // namespace fl
