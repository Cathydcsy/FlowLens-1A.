#include "flowlens/pcap_file.hpp"
#include <algorithm>
#include <array>
#include <istream>
#include <limits>
#include <stdexcept>

namespace fl {
namespace {
constexpr uint32_t maxPacket = 16 * 1024 * 1024, maxBlock = 32 * 1024 * 1024;
uint16_t u16(const uint8_t* p, bool little) {
    return little ? uint16_t(p[0] | (unsigned(p[1]) << 8)) : uint16_t((unsigned(p[0]) << 8) | p[1]);
}
uint32_t u32(const uint8_t* p, bool little) {
    return little ? uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24)
                  : (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
uint64_t u64(const uint8_t* p, bool little) {
    return little ? uint64_t(u32(p, true)) | (uint64_t(u32(p + 4, true)) << 32)
                  : (uint64_t(u32(p, false)) << 32) | u32(p + 4, false);
}
void exact(std::istream& in, uint8_t* p, size_t size) {
    if (size) in.read(reinterpret_cast<char*>(p), std::streamsize(size));
    if (size && size_t(in.gcount()) != size) throw std::runtime_error("Truncated PCAPNG block");
}
template<class Action> void options(const std::vector<uint8_t>& block, size_t start, size_t end,
                                   bool little, Action action) {
    while (start < end) {
        if (end - start < 4) throw std::runtime_error("Truncated PCAPNG option header");
        unsigned code = u16(block.data() + start, little), length = u16(block.data() + start + 2, little);
        start += 4;
        if (code == 0) {
            if (length != 0 || start != end) throw std::runtime_error("Invalid PCAPNG end-of-options");
            return;
        }
        size_t padded = (size_t(length) + 3) & ~size_t(3);
        if (padded > end - start) throw std::runtime_error("Truncated PCAPNG option value");
        action(code, block.data() + start, length);
        start += padded;
    }
}
struct Interface {
    uint32_t link, snaplen;
    uint8_t resolution = 6;
    int64_t offset = 0;
};
uint64_t timestamp(uint64_t ticks, const Interface& iface) {
    const uint64_t max = std::numeric_limits<uint64_t>::max();
    uint64_t ns = 0;
    unsigned exponent = iface.resolution & 127;
    if (!(iface.resolution & 128)) {
        uint64_t factor = 1;
        unsigned power = exponent > 9 ? exponent - 9 : 9 - exponent;
        if (power >= 20) ns = 0; // 任意 uint64 tick 值都小于 1 纳秒。
        else {
            while (power--) factor *= 10;
            if (exponent <= 9) {
                if (ticks > max / factor) throw std::runtime_error("PCAPNG timestamp overflows nanoseconds");
                ns = ticks * factor;
            } else ns = ticks / factor;
        }
    } else {
        // 精确计算 64 位乘 32 位的 96 位乘积，不使用浮点，也不依赖编译器特有的 __int128。
        uint64_t lowProduct = (ticks & 0xffffffffULL) * 1000000000ULL;
        uint64_t upperProduct = (ticks >> 32) * 1000000000ULL + (lowProduct >> 32);
        uint64_t low = (upperProduct << 32) | (lowProduct & 0xffffffffULL), high = upperProduct >> 32;
        if (exponent == 0) {
            if (high) throw std::runtime_error("PCAPNG timestamp overflows nanoseconds");
            ns = low;
        } else if (exponent < 64) {
            if (high >> exponent) throw std::runtime_error("PCAPNG timestamp overflows nanoseconds");
            ns = (high << (64 - exponent)) | (low >> exponent);
        } else if (exponent < 96) ns = high >> (exponent - 64);
    }
    uint64_t magnitude = iface.offset < 0 ? uint64_t(-(iface.offset + 1)) + 1 : uint64_t(iface.offset);
    if (magnitude > max / 1000000000ULL) throw std::runtime_error("PCAPNG timestamp offset overflows");
    uint64_t delta = magnitude * 1000000000ULL;
    if (iface.offset < 0) {
        if (ns < delta) throw std::runtime_error("PCAPNG timestamp is before supported epoch");
        return ns - delta;
    }
    if (ns > max - delta) throw std::runtime_error("PCAPNG timestamp offset overflows");
    return ns + delta;
}
}

PcapSummary readPcapNg(std::istream& in, const std::function<bool(Packet&&)>& consume, size_t maxPackets) {
    PcapSummary summary;
    summary.pcapng = summary.nanoseconds = true;
    summary.sections = summary.interfaces = 0;
    std::vector<Interface> interfaces;
    bool little = true, section = false, knownSectionLength = false;
    uint64_t remaining = 0;
    for (size_t blocks = 0;; ++blocks) {
        std::array<uint8_t, 8> header{};
        in.read(reinterpret_cast<char*>(header.data()), header.size());
        if (!in.gcount()) {
            if (in.bad()) throw std::runtime_error("PCAPNG input read failed");
            if (knownSectionLength && remaining) throw std::runtime_error("Truncated PCAPNG section");
            return summary;
        }
        if (in.gcount() != 8) throw std::runtime_error("Truncated PCAPNG block header");
        if (blocks >= 1000000) throw std::runtime_error("PCAPNG block count exceeds limit");
        bool shb = u32(header.data(), true) == 0x0a0d0d0a;
        std::array<uint8_t, 4> magic{};
        if (shb) {
            if (knownSectionLength && remaining) throw std::runtime_error("PCAPNG section length mismatch");
            exact(in, magic.data(), magic.size());
            if (u32(magic.data(), true) == 0x1a2b3c4d) little = true;
            else if (u32(magic.data(), false) == 0x1a2b3c4d) little = false;
            else throw std::runtime_error("Invalid PCAPNG byte-order magic");
        } else if (!section) throw std::runtime_error("PCAPNG must begin with a section header");
        uint32_t type = u32(header.data(), little), length = u32(header.data() + 4, little);
        if (length < (shb ? 28u : 12u) || length % 4 || length > maxBlock)
            throw std::runtime_error("Invalid PCAPNG block length (limit 32 MiB)");
        if (!shb && knownSectionLength) {
            if (length > remaining) throw std::runtime_error("PCAPNG block exceeds declared section length");
            remaining -= length;
        }
        std::vector<uint8_t> body(length - 8);
        if (shb) {
            std::copy(magic.begin(), magic.end(), body.begin());
            exact(in, body.data() + 4, body.size() - 4);
        } else exact(in, body.data(), body.size());
        size_t end = body.size() - 4;
        if (u32(body.data() + end, little) != length) throw std::runtime_error("PCAPNG trailing block length mismatch");
        if (shb) {
            if (++summary.sections > 1024) throw std::runtime_error("PCAPNG section count exceeds limit");
            if (u16(body.data() + 4, little) != 1 || u16(body.data() + 6, little) != 0)
                throw std::runtime_error("Unsupported PCAPNG section version (requires 1.0)");
            uint64_t size = u64(body.data() + 8, little);
            if (size != uint64_t(-1) && (size >> 63)) throw std::runtime_error("Invalid PCAPNG section length");
            knownSectionLength = size != uint64_t(-1); remaining = size;
            options(body, 16, end, little, [](unsigned, const uint8_t*, unsigned) {});
            interfaces.clear(); section = true; continue;
        }
        if (type == 1) {
            if (end < 8) throw std::runtime_error("Truncated PCAPNG interface description");
            if (interfaces.size() >= 4096) throw std::runtime_error("PCAPNG interface count exceeds limit");
            Interface iface{u16(body.data(), little), u32(body.data() + 4, little)};
            bool resolution = false, offset = false;
            options(body, 8, end, little, [&](unsigned code, const uint8_t* value, unsigned size) {
                if (code == 9) {
                    if (size != 1 || resolution) throw std::runtime_error("Invalid or duplicate PCAPNG if_tsresol");
                    iface.resolution = value[0]; resolution = true;
                } else if (code == 14) {
                    if (size != 8 || offset) throw std::runtime_error("Invalid or duplicate PCAPNG if_tsoffset");
                    uint64_t bits = u64(value, little);
                    iface.offset = bits >> 63 ? -1 - int64_t(~bits) : int64_t(bits); offset = true;
                }
            });
            if (!summary.interfaces) { summary.linkType = iface.link; summary.snaplen = iface.snaplen; }
            else summary.mixedLinkTypes |= summary.linkType != iface.link;
            ++summary.interfaces; interfaces.push_back(iface); continue;
        }
        if (type != 6 && type != 3 && type != 2) { ++summary.skippedBlocks; continue; }
        size_t fixed = type == 3 ? 4 : 20;
        if (end < fixed) throw std::runtime_error("Truncated PCAPNG packet block");
        uint32_t index = type == 3 ? 0 : type == 2 ? u16(body.data(), little) : u32(body.data(), little);
        if (index >= interfaces.size()) throw std::runtime_error("PCAPNG packet references an unknown interface");
        const auto& iface = interfaces[index];
        uint32_t original = u32(body.data() + (type == 3 ? 0 : 16), little);
        uint32_t captured = type == 3 ? (iface.snaplen ? std::min(original, iface.snaplen) : original)
                                      : u32(body.data() + 12, little);
        if (captured > original || captured > maxPacket || (iface.snaplen && captured > iface.snaplen))
            throw std::runtime_error("Invalid PCAPNG packet length (limit 16 MiB)");
        size_t padded = (size_t(captured) + 3) & ~size_t(3);
        if (padded > end - fixed) throw std::runtime_error("Truncated PCAPNG packet data");
        if (type == 3) {
            if (fixed + padded != end) throw std::runtime_error("Invalid PCAPNG simple packet block length");
        } else options(body, fixed + padded, end, little, [](unsigned, const uint8_t*, unsigned) {});
        if (summary.packets >= maxPackets) throw std::runtime_error("PCAPNG packet count exceeds configured limit");
        Packet p;
        p.id = ++summary.packets; p.originalLength = original; p.linkType = iface.link;
        p.interfaceId = index; p.sectionId = uint32_t(summary.sections - 1);
        p.timestampAvailable = type != 3;
        if (p.timestampAvailable) p.timestampNs = timestamp((uint64_t(u32(body.data() + 4, little)) << 32) |
                                                         u32(body.data() + 8, little), iface);
        p.bytes.assign(body.begin() + fixed, body.begin() + fixed + captured);
        if (!consume(std::move(p))) return summary;
    }
}
} // namespace fl
