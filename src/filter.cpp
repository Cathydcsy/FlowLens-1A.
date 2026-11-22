#include "flowlens/filter.hpp"
#include <algorithm>
#include <cctype>
#include <set>
#include <stdexcept>

namespace fl {
namespace {
using Pred = std::function<bool(const Packet&)>;
std::string lower(std::string s) {
    for (auto& c : s)
        c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
struct Token {
    std::string value;
    size_t at;
    bool quoted = false;
};
std::vector<Token> lex(const std::string& s) {
    std::vector<Token> v;
    size_t i = 0;
    while (i < s.size()) {
        if (std::isspace(static_cast<unsigned char>(s[i]))) {
            i++;
            continue;
        }
        size_t at = i;
        std::string word;
        if (s[i] == '"' || s[i] == '\'') {
            char quote = s[i++];
            bool closed = false;
            while (i < s.size()) {
                char c = s[i++];
                if (c == quote) {
                    closed = true;
                    break;
                }
                if (c == '\\' && i < s.size())
                    c = s[i++];
                word += c;
            }
            if (!closed)
                throw std::runtime_error("Unclosed string at column " + std::to_string(at + 1));
            v.push_back({word, at, true});
        } else if (std::string("()=!<>&|").find(s[i]) != std::string::npos) {
            word += s[i++];
            if (i < s.size() &&
                ((s[i] == '=' && (word == "=" || word == "!" || word == "<" || word == ">")) ||
                 (s[i] == '&' && word == "&") || (s[i] == '|' && word == "|")))
                word += s[i++];
            v.push_back({word, at});
        } else {
            while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i])) &&
                   std::string("()=!<>&|").find(s[i]) == std::string::npos)
                word += s[i++];
            v.push_back({word, at});
        }
        if (v.size() > 256)
            throw std::runtime_error("Filter exceeds 256 tokens");
    }
    v.push_back({"", s.size()});
    return v;
}
struct Parser {
    std::vector<Token> t;
    size_t at = 0;
    int depth = 0;
    explicit Parser(const std::string& s) : t(lex(s)) {}
    std::string peek() const {
        return lower(t.at(at).value);
    }
    bool take(const char* v) {
        if (!t[at].quoted && peek() == v) {
            at++;
            return true;
        }
        return false;
    }
    [[noreturn]] void fail(const std::string& s) const {
        throw std::runtime_error(s + " at column " + std::to_string(t.at(at).at + 1));
    }
    Pred expression() {
        auto left = conjunction();
        while (take("or") || take("||")) {
            auto right = conjunction();
            left = [left, right](const Packet& p) { return left(p) || right(p); };
        }
        return left;
    }
    Pred conjunction() {
        auto left = unary();
        while (take("and") || take("&&")) {
            auto right = unary();
            left = [left, right](const Packet& p) { return left(p) && right(p); };
        }
        return left;
    }
    Pred unary() {
        if (++depth > 32)
            fail("Filter nesting exceeds 32");
        Pred p;
        if (take("not") || take("!")) {
            auto c = unary();
            p = [c](const Packet& q) { return !c(q); };
        } else if (take("(")) {
            p = expression();
            if (!take(")"))
                fail("Expected closing parenthesis");
        } else
            p = predicate();
        depth--;
        return p;
    }
    Pred predicate() {
        if (t[at].quoted || peek().empty())
            fail("Expected protocol or field");
        auto name = peek();
        at++;
        static const std::set<std::string> protocols = {
            "tcp", "udp", "http", "dns", "tls", "arp", "icmp", "icmpv6", "ip", "ipv4", "ipv6", "malformed"};
        if (protocols.count(name))
            return [name](const Packet& p) {
                if (name == "tcp")
                    return p.transport == 6;
                if (name == "udp")
                    return p.transport == 17;
                if (name == "ip" || name == "ipv4")
                    return p.ipVersion == 4;
                if (name == "ipv6")
                    return p.ipVersion == 6;
                if (name == "icmp")
                    return p.transport == 1;
                if (name == "icmpv6")
                    return p.transport == 58;
                if (name == "malformed")
                    return !p.warnings.empty();
                return lower(p.protocol) == name;
            };
        static const std::set<std::string> numeric = {"port",     "tcp.port", "udp.port", "src.port",
                                                      "dst.port", "len",      "caplen",   "pid",
                                                      "flow",     "tcp.seq",  "tcp.ack"};
        static const std::set<std::string> strings = {"ip.addr",   "ip.src",   "ip.dst", "process",
                                                      "http.host", "protocol", "info"};
        bool number = numeric.count(name) != 0;
        if (!number && !strings.count(name))
            fail("Unknown field '" + name + "'");
        auto op = peek();
        if (op != "==" && op != "!=" && op != ">" && op != "<" && op != ">=" && op != "<=" &&
            op != "contains")
            fail("Expected comparison operator");
        at++;
        if (peek().empty() && !t[at].quoted)
            fail("Expected comparison value");
        auto value = t[at++].value;
        uint64_t n = 0;
        if (number) {
            if (op == "contains")
                fail("contains requires a string field");
            if (value.empty() || value.size() > 20 ||
                !std::all_of(value.begin(), value.end(), [](char c) { return c >= '0' && c <= '9'; }))
                fail("Expected unsigned integer");
            n = std::stoull(value);
        } else if (op != "==" && op != "!=" && op != "contains")
            fail("String field supports ==, != and contains");
        return [name, op, value, n, number](const Packet& p) {
            if (name.rfind("ip.", 0) == 0 && !p.ipVersion)
                return false;
            if ((name == "tcp.seq" || name == "tcp.ack") && p.transport != 6)
                return false;
            if ((name == "port" || name == "src.port" || name == "dst.port") && p.transport != 6 &&
                p.transport != 17)
                return false;
            if (name == "http.host" && p.httpHost.empty())
                return false;
            if (name == "process" && p.process.empty() && p.peerProcess.empty() && p.flowProcesses.empty())
                return false;
            if ((name == "tcp.port" && p.transport != 6) || (name == "udp.port" && p.transport != 17))
                return false;
            if (number) {
                std::vector<uint64_t> values;
                if (name == "port" || name == "tcp.port" || name == "udp.port")
                    values = {p.sourcePort, p.destinationPort};
                else if (name == "src.port")
                    values = {p.sourcePort};
                else if (name == "dst.port")
                    values = {p.destinationPort};
                else if (name == "len")
                    values = {p.originalLength};
                else if (name == "caplen")
                    values = {p.bytes.size()};
                else if (name == "pid") {
                    if (p.pid) values.push_back(p.pid);
                    if (p.peerPid) values.push_back(p.peerPid);
                    for (const auto& owner : p.flowProcesses)
                        values.push_back(owner.first);
                    if (values.empty()) values.push_back(0);
                }
                else if (name == "flow")
                    values = {p.flowId};
                else if (name == "tcp.seq")
                    values = {p.sequence};
                else
                    values = {p.acknowledgment};
                bool hit = false;
                for (auto x : values) {
                    if (op == "==" || op == "!=")
                        hit |= x == n;
                    else if (op == ">")
                        hit |= x > n;
                    else if (op == "<")
                        hit |= x < n;
                    else if (op == ">=")
                        hit |= x >= n;
                    else
                        hit |= x <= n;
                }
                return op == "!=" ? !hit : hit;
            }
            std::vector<std::string> values;
            if (name == "ip.addr")
                values = {p.source, p.destination};
            else if (name == "ip.src")
                values = {p.source};
            else if (name == "ip.dst")
                values = {p.destination};
            else if (name == "process") {
                values = {p.process, p.peerProcess};
                for (const auto& owner : p.flowProcesses)
                    values.push_back(owner.second);
            }
            else if (name == "http.host")
                values = {p.httpHost};
            else if (name == "protocol")
                values = {p.protocol};
            else
                values = {p.info};
            bool hit = false;
            for (const auto& x : values)
                hit |= op == "contains" ? lower(x).find(lower(value)) != std::string::npos
                                        : lower(x) == lower(value);
            return op == "!=" ? !hit : hit;
        };
    }
};
} // namespace
bool DisplayFilter::compile(const std::string& expression, std::string& error) {
    try {
        Parser p(expression);
        Pred next;
        if (p.peek().empty())
            next = [](const Packet&) { return true; };
        else {
            next = p.expression();
            if (!p.peek().empty())
                p.fail("Unexpected token");
        }
        predicate_ = std::move(next);
        error.clear();
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}
} // namespace fl
