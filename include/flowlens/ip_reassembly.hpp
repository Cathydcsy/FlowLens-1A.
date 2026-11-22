#pragma once
#include "packet.hpp"
#include <map>

namespace fl {
struct IpReassemblyLimits {
    size_t maxEntries = 256, maxDatagramBytes = 65535, maxBufferBytes = 8 * 1024 * 1024,
           maxPieces = 512;
    uint64_t ttlNs = 30000000000ULL;
};
struct IpReassemblyStats {
    uint64_t fragments = 0, completed = 0, duplicates = 0, overlaps = 0,
             rejected = 0, expired = 0, evicted = 0, limited = 0, incomplete = 0;
};
class IpReassembler {
    struct Piece { std::vector<uint8_t> bytes; bool more; uint64_t packetId; };
    struct Entry {
        uint64_t firstSeen = 0;
        std::map<size_t, Piece> pieces;
        std::vector<uint8_t> prefix;
        size_t total = 0, bytes = 0;
        bool hasEnd = false, blocked = false;
        IpFragment first;
    };
    std::map<std::string, Entry> entries_;
    IpReassemblyLimits limits_;
    IpReassemblyStats stats_;
    uint64_t watermark_ = 0;
    size_t buffered_ = 0;
    void erase(std::map<std::string, Entry>::iterator it);
  public:
    explicit IpReassembler(IpReassemblyLimits limits = {}) : limits_(limits) {}
    void ingest(Packet& packet); // 先调用 parse(packet)，原始字节保持不变。
    void expire(uint64_t timestampNs);
    void finish(); // 捕获结束时统计并释放未完成的数据报。
    void clear();
    size_t pending() const;
    size_t buffered() const { return buffered_; }
    const IpReassemblyStats& stats() const { return stats_; }
};
} // namespace fl
