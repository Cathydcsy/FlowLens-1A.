#pragma once
#include "packet.hpp"
#include <functional>
#include <string>

namespace fl {
class DisplayFilter {
    std::function<bool(const Packet&)> predicate_ = [](const Packet&) { return true; };

  public:
    // Compile transactionally: invalid expressions leave the previous filter intact.
    bool compile(const std::string& expression, std::string& error);
    bool matches(const Packet& p) const {
        return predicate_(p);
    }
};
} // namespace fl
