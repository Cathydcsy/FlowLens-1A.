#pragma once
#include "packet.hpp"
#include <functional>

namespace fl {
struct PcapSummary {
    uint32_t linkType = 1, snaplen = 65535;
    size_t packets = 0;
    bool nanoseconds = false;
    bool pcapng = false, mixedLinkTypes = false;
    size_t interfaces = 1, sections = 1, skippedBlocks = 0;
};
PcapSummary readPcap(const std::string& path, const std::function<bool(Packet&&)>& consume,
                     size_t maxPackets = 200000);
void writePcap(const std::string& path, const std::vector<Packet>& packets, uint32_t linkType = 1);
} // namespace fl
