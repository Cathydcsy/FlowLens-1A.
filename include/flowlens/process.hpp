#pragma once
#include "packet.hpp"
#include <unordered_map>
namespace fl {
struct ProcessIdentity {
    uint32_t pid = 0;
    std::string name;
};
class ProcessResolver {
    std::unordered_map<std::string, ProcessIdentity> endpoints_;

  public:
    bool refresh();
    void attach(Packet& packet) const;
    size_t count() const {
        return endpoints_.size();
    }
};
} // namespace fl
