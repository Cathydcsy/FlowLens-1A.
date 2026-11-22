#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <map>

namespace fl {
struct Field {
    std::string name, value;
    size_t offset = 0, length = 0;
    int depth = 0;
};
enum class ChecksumState { NotAvailable, Verified, Incorrect };
enum class ChecksumMode { Automatic, Strict, OffloadPossible };
struct ChecksumResult {
    ChecksumState state = ChecksumState::NotAvailable;
    uint16_t stored = 0, computed = 0;
    std::string reason = "protocol not applicable or not fully decoded";
};
const char* checksumStateName(ChecksumState state);
uint16_t internetChecksum(const uint8_t* data, size_t length, uint32_t seed = 0,
                          size_t zeroOffset = size_t(-1));
struct IpFragment {
    bool present = false, more = false, complete = false;
    uint32_t identification = 0;
    size_t offset = 0, payloadOffset = 0, payloadLength = 0, ipOffset = 0,
           headerLength = 0, previousNextHeader = 0;
    uint8_t nextHeader = 0;
};
struct Packet {
    uint64_t id = 0, timestampNs = 0, flowId = 0;
    uint32_t originalLength = 0, linkType = 1, pid = 0, peerPid = 0;
    std::vector<uint8_t> bytes;
    std::vector<Field> fields;
    std::vector<std::string> warnings;
    std::string source, destination, protocol = "Unknown", info, process, peerProcess, httpHost;
    // Flow-level evidence is separate from the packet's direct PID snapshot.
    std::map<uint32_t, std::string> flowProcesses;
    uint16_t sourcePort = 0, destinationPort = 0;
    uint8_t ipVersion = 0, transport = 0, tcpFlags = 0;
    uint32_t sequence = 0, acknowledgment = 0;
    size_t payloadOffset = 0, payloadLength = 0;
    bool fragmented = false;
    ChecksumMode checksumMode = ChecksumMode::Automatic;
    ChecksumResult ipChecksum, transportChecksum;
    uint32_t interfaceId = 0, sectionId = 0;
    bool timestampAvailable = true;
    IpFragment fragment;
    std::string reassemblyStatus;
    std::shared_ptr<Packet> reassembled;
    std::vector<uint64_t> reassembledFrom;
};
void parse(Packet& packet);
std::string address(const uint8_t* data, int family);
std::string endpoint(const std::string& ip, uint16_t port);
std::string tcpFlags(uint8_t flags);
std::string printable(const std::vector<uint8_t>& bytes);
std::string identifyHttp(const std::vector<uint8_t>& bytes, std::string* host = nullptr);
std::string inspectHttp(const std::vector<uint8_t>& bytes);
std::string jsonEscape(const std::string& text, bool preserveUtf8 = false);
std::string packetJson(const Packet& packet);
} // namespace fl
