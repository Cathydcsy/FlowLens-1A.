#pragma once
#include "packet.hpp"
#include <map>
#include <memory>
#include <unordered_map>

namespace fl {
class DirectionStream {
  public:
    static constexpr size_t limit = 128 * 1024;
    bool hasBase = false, fromSyn = false, limited = false;
    uint32_t base = 0;
    size_t buffered = 0, retransmitted = 0, conflicts = 0, outOfOrder = 0;
    std::map<int64_t, std::vector<uint8_t>> chunks;
    void establish(uint32_t seq, bool syn);
    void insert(uint32_t seq, const uint8_t* data, size_t size);
    std::vector<uint8_t> contiguous() const;
    std::string text() const;
    size_t gaps() const;
};
struct FlowEvent {
    uint64_t packetId = 0, time = 0;
    bool reverse = false;
    std::string flags;
    size_t payload = 0;
};
struct Flow {
    uint64_t id = 0, firstNs = 0, lastNs = 0, packets = 0, bytes = 0;
    std::string a, b, application = "TCP", process;
    uint16_t portA = 0, portB = 0;
    uint32_t pid = 0, synSequence = 0;
    uint32_t interfaceId = 0, sectionId = 0;
    std::map<uint32_t, std::string> owners;
    bool closed = false, hasSyn = false, synReverse = false;
    unsigned finMask = 0;
    DirectionStream directions[2];
    std::vector<FlowEvent> events;
    std::string httpAnalysis() const;
};
class FlowTable {
    uint64_t nextId_ = 1;
    std::unordered_map<std::string, uint64_t> active_;
    std::map<uint64_t, std::shared_ptr<Flow>> flows_;

  public:
    static constexpr size_t maxFlows = 512, globalBufferLimit = 32 * 1024 * 1024;
    size_t evicted = 0;
    std::shared_ptr<Flow> ingest(Packet& p);
    std::shared_ptr<Flow> get(uint64_t id) const;
    bool syncProcessOwners(Packet& packet) const;
    const std::map<uint64_t, std::shared_ptr<Flow>>& all() const {
        return flows_;
    }
    size_t buffered() const;
    void clear();
};
} // namespace fl
