#pragma once
#include "packet.hpp"
#include <functional>
#include <string>

namespace fl {
class DisplayFilter {
    std::function<bool(const Packet&)> predicate_ = [](const Packet&) { return true; };

  public:
    // 采用事务式编译：表达式非法时保留上一条有效过滤条件。
    bool compile(const std::string& expression, std::string& error);
    bool matches(const Packet& p) const {
        return predicate_(p);
    }
};
} // namespace fl
