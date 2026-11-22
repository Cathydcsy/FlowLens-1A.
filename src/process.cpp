#include "flowlens/process.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <vector>

namespace fl {
namespace {
std::string processName(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return "Unknown (access restricted)";
    wchar_t buffer[32768]{};
    DWORD n = 32768;
    BOOL ok = QueryFullProcessImageNameW(h, 0, buffer, &n);
    CloseHandle(h);
    if (!ok)
        return "Unknown";
    std::wstring path(buffer, n);
    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        path = path.substr(slash + 1);
    int size = WideCharToMultiByte(CP_UTF8, 0, path.data(), int(path.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, path.data(), int(path.size()), s.data(), size, nullptr, nullptr);
    return s;
}
std::string key(const std::string& src, uint16_t sp, const std::string& dst, uint16_t dp) {
    return endpoint(src, sp) + "/" + endpoint(dst, dp);
}
} // namespace
bool ProcessResolver::refresh() {
    std::unordered_map<std::string, ProcessIdentity> next;
    std::unordered_map<DWORD, std::string> names;
    bool success = false;
    auto identity = [&](DWORD pid) {
        auto it = names.find(pid);
        if (it == names.end())
            it = names.emplace(pid, processName(pid)).first;
        return ProcessIdentity{pid, it->second};
    };
    for (ULONG family : {ULONG(AF_INET), ULONG(AF_INET6)}) {
        DWORD size = 0;
        DWORD code = GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (code != ERROR_INSUFFICIENT_BUFFER || size > 16 * 1024 * 1024)
            continue;
        std::vector<uint8_t> buffer(size);
        code = GetExtendedTcpTable(buffer.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (code != NO_ERROR)
            continue;
        success = true;
        if (family == AF_INET) {
            auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                const auto& r = table->table[i];
                if (r.dwState == MIB_TCP_STATE_LISTEN)
                    continue;
                next[key(address(reinterpret_cast<const uint8_t*>(&r.dwLocalAddr), 4),
                         ntohs(USHORT(r.dwLocalPort)),
                         address(reinterpret_cast<const uint8_t*>(&r.dwRemoteAddr), 4),
                         ntohs(USHORT(r.dwRemotePort)))] = identity(r.dwOwningPid);
            }
        } else {
            auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                const auto& r = table->table[i];
                if (r.dwState == MIB_TCP_STATE_LISTEN)
                    continue;
                next[key(address(r.ucLocalAddr, 6), ntohs(USHORT(r.dwLocalPort)), address(r.ucRemoteAddr, 6),
                         ntohs(USHORT(r.dwRemotePort)))] = identity(r.dwOwningPid);
            }
        }
    }
    endpoints_.swap(next);
    return success;
}
void ProcessResolver::attach(Packet& p) const {
    if (p.transport != 6)
        return;
    auto it = endpoints_.find(key(p.source, p.sourcePort, p.destination, p.destinationPort));
    if (it != endpoints_.end()) {
        p.pid = it->second.pid;
        p.process = it->second.name;
    }
    auto peer = endpoints_.find(key(p.destination, p.destinationPort, p.source, p.sourcePort));
    if (peer != endpoints_.end()) {
        if (!p.pid) {
            p.pid = peer->second.pid;
            p.process = peer->second.name;
        } else if (peer->second.pid != p.pid) {
            p.peerPid = peer->second.pid;
            p.peerProcess = peer->second.name;
        }
    }
}
} // namespace fl
