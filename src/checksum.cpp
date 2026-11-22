#include "flowlens/packet.hpp"

namespace fl {
const char* checksumStateName(ChecksumState state) {
    switch (state) {
    case ChecksumState::Verified: return "verified";
    case ChecksumState::Incorrect: return "incorrect";
    default: return "not available";
    }
}
uint16_t internetChecksum(const uint8_t* data, size_t length, uint32_t seed, size_t zeroOffset) {
    uint64_t sum = seed;
    for (size_t i = 0; i < length; i += 2) {
        bool zeroHigh = zeroOffset < length && i >= zeroOffset && i - zeroOffset < 2;
        bool zeroLow = zeroOffset < length && i + 1 >= zeroOffset && i + 1 - zeroOffset < 2;
        unsigned high = zeroHigh ? 0 : data[i];
        unsigned low = i + 1 < length && !zeroLow ? data[i + 1] : 0;
        sum += (high << 8) | low;
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}
} // namespace fl
