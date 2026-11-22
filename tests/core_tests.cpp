#include "flowlens/packet.hpp"
#include "flowlens/stream.hpp"
#include "flowlens/filter.hpp"
#include "flowlens/pcap_file.hpp"
#include <fstream>
#include <array>
#include <iostream>
#include <random>
#include <stdexcept>
#include <cstdio>
#ifdef _WIN32
#include <winsock2.h>
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#endif
static int count = 0;
void check(bool yes, const char* name) {
    count++;
    if (!yes)
        throw std::runtime_error(std::string("FAILED: ") + name);
    std::cout << "PASS " << name << "\n";
}
int main(int argc, char** argv) {
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_EVERY_1024_DF);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
#ifdef _WIN32
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);
#endif
    try {
        std::string root = argc > 1 ? argv[1] : "samples";
        std::vector<fl::Packet> packets;
        fl::FlowTable flows;
        auto summary = fl::readPcap(root + "/showcase.pcap", [&](fl::Packet&& p) {
            fl::parse(p);
            flows.ingest(p);
            packets.push_back(std::move(p));
            return true;
        });
        check(summary.packets == 22, "fixture packet count");
        check(flows.all().size() == 4, "canonical bidirectional flow count");
        check(packets[0].sequence == 1000 && packets[0].sourcePort == 51000, "TCP fields decoded");
        check(packets[0].source == "192.0.2.10" && packets[0].destination == "198.51.100.20",
              "IPv4 addresses decoded");
        auto f = flows.get(1);
        check(f && f->application == "HTTP", "nonstandard port HTTP discovered after reassembly");
        check(f->directions[0].gaps() == 0 && f->directions[1].gaps() == 0, "out-of-order gap closed");
        check(f->directions[0].retransmitted == 29, "TCP retransmission deduplicated");
        check(f->directions[0].outOfOrder >= 1, "out-of-order segment counted");
        check(f->closed, "bidirectional FIN closes flow");
        check(f->httpAnalysis().find("Body complete: 20 bytes") != std::string::npos, "HTTP body framing");
        check(f->directions[0].text().find("GET /lab?course=security HTTP/1.1") != std::string::npos,
              "request reconstructed exactly");
        check(f->directions[1].text().find("Hello from FlowLens!") != std::string::npos,
              "response reconstructed");
        check(packets[10].protocol == "DNS" && packets[11].info.find("198.51.100.20") != std::string::npos,
              "DNS pointer compression and A answer");
        check(packets[12].protocol == "ICMP" && packets[13].protocol == "ARP", "ICMP and ARP");
        check(packets[14].ipVersion == 6 && packets[14].source == "2001:db8::10", "IPv6 addresses");
        check(packets[17].protocol == "ICMPv6" && packets[19].protocol == "TLS", "ICMPv6 and TLS record");
        check(packets[21].protocol == "TCP", "port 80 alone does not imply HTTP");
        fl::DisplayFilter filter;
        std::string error;
        check(filter.compile("tcp and (port == 18080 or ipv6)", error), "boolean filter compiles");
        check(filter.matches(packets[0]) && !filter.matches(packets[10]), "boolean filter evaluation");
        check(filter.compile("ip.addr != 192.0.2.10", error) && !filter.matches(packets[0]),
              "address inequality applies to both endpoints");
        check(filter.compile("udp or tcp and port == 80", error) && filter.matches(packets[10]) &&
                  !filter.matches(packets[0]),
              "and precedence over or");
        check(!filter.compile("tcp and (", error), "invalid filter rejected");
        check(filter.matches(packets[10]), "invalid compile preserves previous filter");
        check(!filter.compile("unknown == 3", error), "unknown field rejected");
        check(!filter.compile("len == -1", error), "negative numeric filter rejected");
        check(filter.compile("info contains \"lab.example\"", error) && filter.matches(packets[10]),
              "quoted string predicate");
        check(filter.compile("not (arp or udp)", error) && filter.matches(packets[0]) &&
                  !filter.matches(packets[13]),
              "not and parentheses");
        check(filter.compile("tcp.seq == 0", error) && !filter.matches(packets[10]),
              "absent TCP field does not match UDP");
        check(filter.compile("port == 0", error) && !filter.matches(packets[13]),
              "absent port does not match ARP");
        check(filter.compile("ip.addr == 192.0.2.10", error) && !filter.matches(packets[13]),
              "IP fields require an IP layer");
        fl::DirectionStream stream;
        stream.establish(100, true);
        const uint8_t abc[] = {'a', 'b', 'c'};
        stream.insert(103, abc, 3);
        check(stream.gaps() == 1 && stream.contiguous().empty(), "missing leading bytes remain visible");
        stream.insert(100, abc, 3);
        check(stream.gaps() == 0 && stream.text() == "abcabc", "adjacent segments merge");
        const uint8_t xyz[] = {'x', 'y', 'z'};
        stream.insert(100, xyz, 3);
        check(stream.conflicts == 3 && stream.text() == "abcabc", "conflicting overlap first-seen policy");
        fl::DirectionStream wrap;
        wrap.establish(0xfffffffe, true);
        wrap.insert(0xfffffffe, abc, 3);
        wrap.insert(1, abc, 3);
        check(wrap.text() == "abcabc", "32-bit TCP sequence wraparound");
        std::vector<uint8_t> huge(fl::DirectionStream::limit + 1);
        wrap.insert(5, huge.data(), huge.size());
        check(wrap.limited && wrap.buffered <= fl::DirectionStream::limit, "stream byte cap enforced");
        for (auto name : {"big_endian.pcap", "nanoseconds.pcap", "loopback.pcap", "raw_ipv6.pcap",
                          "vlan.pcap", "ipv6_extensions.pcap", "ipv6_empty.pcap"}) {
            size_t clean = 0;
            fl::readPcap(root + "/" + name, [&](fl::Packet&& p) {
                fl::parse(p);
                if (p.warnings.empty())
                    clean++;
                return true;
            });
            check(clean > 0, name);
        }
        size_t bad = 0;
        fl::readPcap(root + "/edge_cases.pcap", [&](fl::Packet&& p) {
            fl::parse(p);
            bad += !p.warnings.empty();
            return true;
        });
        check(bad >= 4, "truncated and fragmented packets reported safely");
        bool rejected = false;
        try {
            fl::readPcap(root + "/truncated_record.pcap", [](fl::Packet&&) { return true; });
        } catch (...) {
            rejected = true;
        }
        check(rejected, "truncated PCAP data rejected");
        const auto roundtripPath = root + "/.flowlens-roundtrip-test.pcap";
        fl::writePcap(roundtripPath, packets, 1);
        size_t roundtrip = 0;
        bool same = true;
        fl::readPcap(roundtripPath, [&](fl::Packet&& p) {
            same &= p.bytes == packets[roundtrip].bytes && p.timestampNs == packets[roundtrip].timestampNs;
            roundtrip++;
            return true;
        });
        std::remove(roundtripPath.c_str());
        check(same && roundtrip == packets.size(), "PCAP nanosecond save/read round trip");
        fl::FlowTable chunked;
        fl::readPcap(root + "/chunked.pcap", [&](fl::Packet&& p) {
            fl::parse(p);
            chunked.ingest(p);
            return true;
        });
        check(chunked.get(1)->httpAnalysis().find("11 decoded bytes; complete") != std::string::npos,
              "chunked HTTP across sequence wrap");
        std::mt19937 random(7130);
        for (int i = 0; i < 12000; i++) {
            fl::Packet p;
            p.linkType = std::array<uint32_t, 7>{1, 0, 101, 113, 276, 999, 108}[random() % 7];
            p.bytes.resize(random() % 256);
            for (auto& b : p.bytes)
                b = uint8_t(random());
            p.originalLength = uint32_t(p.bytes.size());
            fl::parse(p);
            for (const auto& field : p.fields)
                if (field.length &&
                    (field.offset > p.bytes.size() || field.length > p.bytes.size() - field.offset))
                    throw std::runtime_error("field bounds escaped captured data");
        }
        check(true, "12000 deterministic malformed-input cases");
        for (int i = 0; i < 12000; i++) {
            fl::Packet p = packets[random() % packets.size()];
            if (!p.bytes.empty()) {
                for (unsigned j = 0; j < 1 + random() % 5; j++)
                    p.bytes[random() % p.bytes.size()] = uint8_t(random());
                if (i % 3 == 0)
                    p.bytes.resize(random() % p.bytes.size());
            }
            fl::parse(p);
            for (const auto& field : p.fields)
                if (field.length &&
                    (field.offset > p.bytes.size() || field.length > p.bytes.size() - field.offset))
                    throw std::runtime_error("mutated packet field bounds escaped");
        }
        check(true, "12000 structured packet mutation cases");
        fl::Packet local;
        local.pid = 100;
        local.peerPid = 200;
        check(filter.compile("pid == 200", error) && filter.matches(local), "loopback peer PID filter");
        auto original = packets[0];
        fl::FlowTable lifecycle;
        lifecycle.ingest(original);
        auto newid = original;
        newid.sequence += 1000;
        newid.timestampNs += 1;
        lifecycle.ingest(newid);
        check(newid.flowId != original.flowId, "tuple reuse creates new TCP connection");
        fl::FlowTable bounded;
        for (unsigned i = 0; i < 600; i++) {
            auto p = packets[0];
            p.sourcePort = uint16_t(1000 + i);
            p.timestampNs += i;
            bounded.ingest(p);
        }
        check(bounded.all().size() == fl::FlowTable::maxFlows && bounded.evicted == 88,
              "flow count bound and eviction");
        check(fl::identifyHttp(std::vector<uint8_t>{'G', 'E', 'T', ' '}).empty(),
              "partial HTTP start line is not misclassified");
#ifdef _DEBUG
        check(_CrtCheckMemory() != 0, "Debug CRT heap integrity");
#endif
        std::cout << "RESULT " << count << " checks passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
