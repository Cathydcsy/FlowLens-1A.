#include "flowlens/packet.hpp"
#include "flowlens/pcap_file.hpp"
#include "flowlens/stream.hpp"
#include "flowlens/filter.hpp"
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#endif

namespace {
int checks = 0;
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
    ++checks;
    std::cout << "PASS " << message << '\n';
}
bool matches(const fl::Packet& packet, const std::string& expression) {
    fl::DisplayFilter filter;
    std::string error;
    if (!filter.compile(expression, error)) throw std::runtime_error(error);
    return filter.matches(packet);
}
}
int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);
#endif
    try {
        const std::string root = argc > 1 ? argv[1] : "samples";
        std::vector<fl::Packet> fixture;
        fl::readPcap(root + "/showcase.pcap", [&](fl::Packet&& p) {
            fl::parse(p); fixture.push_back(std::move(p)); return true;
        });
        fl::FlowTable flows;
        auto early = fixture.at(0);
        flows.ingest(early);
        require(early.flowProcesses.empty(), "handshake without a snapshot stays unknown initially");
        auto later = fixture.at(2);
        later.pid = 101; later.process = "client-A.exe";
        later.peerPid = 202; later.peerProcess = "server.exe";
        flows.ingest(later);
        require(later.flowId == early.flowId && later.flowProcesses.size() == 2,
                "later direct observations establish both owners of the same flow");
        require(flows.syncProcessOwners(early), "earlier retained handshake receives flow association");
        require(early.pid == 0 && early.peerPid == 0 && early.process.empty(),
                "flow association never invents a direct packet PID snapshot");
        require(matches(early, "pid == 101") && matches(early, "pid == 202"),
                "PID filtering includes both owners of an associated loopback flow");
        require(matches(early, "process contains client-A") && matches(early, "process == server.exe"),
                "process-name filtering includes confirmed flow owners");
        require(!matches(early, "pid == 0") && !matches(early, "pid != 101"),
                "associated packets are not classified as unknown or unequal to an owner");
        require(!flows.syncProcessOwners(early), "unchanged association does not trigger another model update");
        const auto json = fl::packetJson(early);
        require(json.find("\"pid\":0") != std::string::npos &&
                    json.find("\"flow_processes\":[{\"pid\":101") != std::string::npos,
                "JSON keeps raw PID and flow ownership in separate fields");
        auto unicodeOwner = early;
        unicodeOwner.flowProcesses[101] = "客户端.exe";
        require(fl::packetJson(unicodeOwner).find("客户端.exe") != std::string::npos,
                "flow process names preserve UTF-8 in JSON");
        auto wrongEndpoint = early;
        wrongEndpoint.source = "203.0.113.99";
        wrongEndpoint.flowProcesses.clear();
        require(!flows.syncProcessOwners(wrongEndpoint) && wrongEndpoint.flowProcesses.empty(),
                "flow ID alone cannot associate unrelated endpoints");
        auto wrongInterface = early;
        wrongInterface.interfaceId = 99;
        wrongInterface.flowProcesses.clear();
        require(!flows.syncProcessOwners(wrongInterface), "association checks the capture interface");
        auto wrongSection = early;
        wrongSection.sectionId = 99;
        wrongSection.flowProcesses.clear();
        require(!flows.syncProcessOwners(wrongSection), "association checks the capture section");
        auto udp = early;
        udp.transport = 17; udp.flowProcesses.clear();
        require(!flows.syncProcessOwners(udp), "non-TCP packet cannot inherit TCP ownership");

        auto newSyn = fixture.at(0);
        newSyn.sequence += 100000;
        flows.ingest(newSyn);
        require(newSyn.flowId != early.flowId && newSyn.flowProcesses.empty(),
                "new SYN generation on reused ports starts with no inherited PID");
        auto newLater = fixture.at(2);
        newLater.sequence += 100000;
        newLater.pid = 303; newLater.process = "client-B.exe";
        newLater.peerPid = 202; newLater.peerProcess = "server.exe";
        flows.ingest(newLater);
        flows.syncProcessOwners(newSyn);
        flows.syncProcessOwners(early);
        require(matches(newSyn, "pid == 303") && !matches(newSyn, "pid == 101"),
                "new connection receives only its own confirmed client");
        require(matches(early, "pid == 101") && !matches(early, "pid == 303"),
                "older retained connection keeps its own generation ownership");
        auto otherInterface = fixture.at(0);
        otherInterface.interfaceId = 1;
        flows.ingest(otherInterface);
        require(otherInterface.flowId != newSyn.flowId && otherInterface.flowProcesses.empty(),
                "same tuple on another interface has independent flow ownership");

        fl::FlowTable offline;
        auto noOwner = fixture.at(0);
        offline.ingest(noOwner);
        offline.syncProcessOwners(noOwner);
        require(noOwner.flowProcesses.empty() && matches(noOwner, "pid == 0"),
                "offline capture never gains a PID without actual ownership evidence");
        auto observed = later;
        auto beforePid = observed.pid;
        flows.syncProcessOwners(observed);
        require(observed.pid == beforePid && observed.process == "client-A.exe",
                "direct snapshot identity is preserved while association is synchronized");
        auto reparsed = early;
        fl::parse(reparsed);
        require(reparsed.flowProcesses.empty(), "reparsing clears stale flow-derived ownership");

        fl::FlowTable assembled;
        auto complete = fixture.at(0);
        complete.pid = 404; complete.process = "fragment-client.exe";
        complete.peerPid = 505; complete.peerProcess = "fragment-server.exe";
        complete.reassembled = std::make_shared<fl::Packet>(fixture.at(0));
        assembled.ingest(complete);
        require(complete.flowProcesses.size() == 2 &&
                    complete.reassembled->flowProcesses == complete.flowProcesses,
                "original completion frame and reassembled datagram share association");
        std::cout << "RESULT " << checks << " attribution checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAILED " << error.what() << '\n';
        return 1;
    }
}
