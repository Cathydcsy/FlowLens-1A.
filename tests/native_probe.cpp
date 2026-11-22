#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "flowlens/capture.hpp"
#include "flowlens/process.hpp"
#include "flowlens/stream.hpp"
#include "flowlens/filter.hpp"
#include "flowlens/pcap_file.hpp"
#include <chrono>
#include <iostream>
#include <fstream>
#include <set>
#include <stdexcept>

int main(int argc, char** argv) {
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);
    if (argc > 2 && std::string(argv[1]) == "--client") {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(18080);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
            closesocket(s);
            return 2;
        }
        std::string request = "GET /client-" + std::string(argv[2]) +
                              " HTTP/1.1\r\nHost: localhost:18080\r\nContent-Length: 0\r\n\r\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        send(s, request.data(), int(request.size()), 0);
        char out[1024];
        recv(s, out, sizeof(out), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(1800));
        shutdown(s, SD_BOTH);
        closesocket(s);
        return 0;
    }
    try {
        fl::Capture capture;
        if (!capture.available())
            throw std::runtime_error(capture.error());
        auto adapters = capture.adapters();
        if (argc > 1 && std::string(argv[1]) == "--list") {
            for (size_t i = 0; i < adapters.size(); i++)
                std::cout << i << " " << adapters[i].name << " " << adapters[i].description << "\n";
            return 0;
        }
        std::string loop;
        for (const auto& a : adapters)
            if (a.name.find("Loopback") != std::string::npos ||
                a.description.find("loopback") != std::string::npos)
                loop = a.name;
        if (loop.empty())
            throw std::runtime_error("Npcap loopback adapter not found");
        bool badFilterRejected = !capture.start(loop, "tcp and (");
        if (!badFilterRejected)
            capture.stop();
        SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(18080);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) || listen(listener, 2)) {
            closesocket(listener);
            throw std::runtime_error("Loopback port 18080 is not available");
        }
        if (!capture.start(loop, "tcp port 18080")) {
            closesocket(listener);
            throw std::runtime_error(capture.error());
        }
        std::thread server([listener] {
            std::vector<std::thread> clients;
            for (int i = 0; i < 2; i++) {
                SOCKET s = accept(listener, nullptr, nullptr);
                if (s == INVALID_SOCKET)
                    break;
                clients.emplace_back([s] {
                    char request[2048];
                    recv(s, request, sizeof(request), 0);
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nFlowLens live OK!";
                    send(s, response.data(), int(response.size()), 0);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1700));
                    shutdown(s, SD_BOTH);
                    closesocket(s);
                });
            }
            for (auto& t : clients)
                t.join();
            closesocket(listener);
        });
        wchar_t self[32768];
        GetModuleFileNameW(nullptr, self, 32768);
        std::vector<PROCESS_INFORMATION> children;
        for (const wchar_t* name : {L"A", L"B"}) {
            std::wstring command = L"\"" + std::wstring(self) + L"\" --client " + name;
            STARTUPINFOW si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            if (!CreateProcessW(self, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                                nullptr, &si, &pi)) {
                capture.stop();
                closesocket(listener);
                server.detach();
                throw std::runtime_error("Cannot start test client");
            }
            CloseHandle(pi.hThread);
            children.push_back(pi);
        }
        fl::ProcessResolver resolver;
        fl::FlowTable flows;
        std::vector<fl::Packet> packets;
        std::set<uint32_t> pids;
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < end) {
            resolver.refresh();
            auto batch = capture.take();
            for (auto& p : batch) {
                p.id = packets.size() + 1;
                fl::parse(p);
                resolver.attach(p);
                flows.ingest(p);
                if (p.pid)
                    pids.insert(p.pid);
                if (p.peerPid)
                    pids.insert(p.peerPid);
                packets.push_back(std::move(p));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        capture.stop();
        auto final = capture.take();
        for (auto& p : final) {
            p.id = packets.size() + 1;
            fl::parse(p);
            flows.ingest(p);
            packets.push_back(std::move(p));
        }
        server.join();
        bool childExit = true;
        for (auto& pi : children) {
            WaitForSingleObject(pi.hProcess, 3000);
            DWORD code = 0;
            GetExitCodeProcess(pi.hProcess, &code);
            childExit &= code == 0;
            CloseHandle(pi.hProcess);
        }
        bool attributed = true;
        for (const auto& pi : children)
            attributed &= pids.count(pi.dwProcessId) > 0;
        size_t http = 0;
        for (const auto& p : packets)
            http += p.protocol == "HTTP";
        size_t restored = 0;
        for (const auto& f : flows.all())
            restored += f.second->httpAnalysis().find("HTTP/1.1 200 OK") != std::string::npos;
        size_t associatedOnly = 0;
        for (auto& p : packets) {
            flows.syncProcessOwners(p);
            associatedOnly += !p.pid && !p.flowProcesses.empty();
        }
        bool pidConsistent = true;
        std::vector<std::pair<uint64_t, uint64_t>> pidCounts;
        for (const auto& pi : children) {
            uint64_t expected = 0, matched = 0;
            for (const auto& entry : flows.all())
                if (entry.second->owners.count(pi.dwProcessId)) expected += entry.second->packets;
            fl::DisplayFilter filter;
            std::string error;
            if (!filter.compile("pid == " + std::to_string(pi.dwProcessId), error))
                throw std::runtime_error(error);
            for (const auto& p : packets) matched += filter.matches(p);
            pidConsistent &= expected > 0 && matched == expected;
            pidCounts.push_back({expected, matched});
        }
        if (argc > 1)
            fl::writePcap(argv[1], packets, packets.empty() ? 0 : packets.front().linkType);
        auto stats = capture.stats();
        bool passed =
            !packets.empty() && http >= 2 && attributed && restored >= 2 && childExit && badFilterRejected && pidConsistent;
        std::cout << "{\"passed\":" << (passed ? "true" : "false") << ",\"packets\":" << packets.size()
                  << ",\"http_packets\":" << http << ",\"restored_http_flows\":" << restored
                  << ",\"client_processes_attributed\":" << (attributed ? "true" : "false")
                  << ",\"invalid_bpf_rejected\":" << (badFilterRejected ? "true" : "false")
                  << ",\"pid_flow_filter_consistent\":" << (pidConsistent ? "true" : "false")
                  << ",\"flow_association_without_direct_pid\":" << associatedOnly
                  << ",\"application_queue_drops\":" << stats.queueDropped
                  << ",\"driver_buffer_drops\":" << stats.driverDropped
                  << ",\"parent_pid\":" << GetCurrentProcessId() << ",\"child_pids\":[";
        for (size_t i = 0; i < children.size(); i++) {
            if (i)
                std::cout << ',';
            std::cout << children[i].dwProcessId;
        }
        std::cout << "],\"pid_packet_counts\":[";
        for (size_t i = 0; i < children.size(); ++i) {
            if (i) std::cout << ',';
            std::cout << "{\"pid\":" << children[i].dwProcessId << ",\"flow_packets\":" << pidCounts[i].first
                      << ",\"matched_packets\":" << pidCounts[i].second << '}';
        }
        std::cout << "]}\n";
        return passed ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
