#include "flowlens/packet.hpp"
#include "flowlens/pcap_file.hpp"
#include "flowlens/filter.hpp"
#include "flowlens/stream.hpp"
#include "flowlens/ip_reassembly.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#ifdef _WIN32
#include <winsock2.h>
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);
#endif
    if (argc < 2) {
        std::cout << "FlowLens CLI\nUsage: flowlens_cli input.pcap [--filter EXPRESSION] [--json "
                     "output.json] [--repeat N]\n";
        return 0;
    }
    try {
        std::string filterText, outPath;
        int repeats = 1;
        fl::ChecksumMode checksumMode = fl::ChecksumMode::Automatic;
        for (int i = 2; i < argc; i++) {
            std::string a = argv[i];
            if (i + 1 >= argc)
                throw std::runtime_error("Missing option value");
            if (a == "--filter")
                filterText = argv[++i];
            else if (a == "--json")
                outPath = argv[++i];
            else if (a == "--checksum-mode") {
                std::string mode = argv[++i];
                if (mode == "auto") checksumMode = fl::ChecksumMode::Automatic;
                else if (mode == "strict") checksumMode = fl::ChecksumMode::Strict;
                else if (mode == "offload") checksumMode = fl::ChecksumMode::OffloadPossible;
                else throw std::runtime_error("Checksum mode must be auto, strict or offload");
            }
            else if (a == "--repeat") {
                repeats = std::stoi(argv[++i]);
                if (repeats < 1 || repeats > 10000)
                    throw std::runtime_error("Invalid repeat count");
            } else
                throw std::runtime_error("Unknown option " + a);
        }
        fl::DisplayFilter filter;
        std::string error;
        if (!filter.compile(filterText, error))
            throw std::runtime_error(error);
        std::map<std::string, size_t> protocols;
        fl::FlowTable flows;
        fl::IpReassembler fragments;
        fl::PcapSummary captureInfo;
        size_t count = 0, matched = 0, warnings = 0;
        std::ostringstream records;
        auto start = std::chrono::steady_clock::now();
        for (int r = 0; r < repeats; r++) {
            captureInfo = fl::readPcap(argv[1], [&](fl::Packet&& p) {
                p.id = ++count;
                p.checksumMode = checksumMode;
                fl::parse(p);
                fragments.ingest(p);
                flows.ingest(p);
                protocols[p.protocol]++;
                warnings += !p.warnings.empty();
                if (filter.matches(p)) {
                    if (matched && !outPath.empty())
                        records << ",\n";
                    matched++;
                    if (!outPath.empty())
                        records << fl::packetJson(p);
                }
                return true;
            });
            fragments.finish();
        }
        double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        std::ostringstream report;
        report << "{\"packets\":" << count << ",\"matched\":" << matched << ",\"warnings\":" << warnings
               << ",\"flows\":" << flows.all().size() << ",\"flow_evictions\":" << flows.evicted
               << ",\"stream_buffer_bytes\":" << flows.buffered() << ",\"elapsed_seconds\":" << seconds
               << ",\"packets_per_second\":" << (seconds ? count / seconds : 0) << ",\"protocols\":{";
        bool comma = false;
        for (const auto& p : protocols) {
            if (comma)
                report << ',';
            comma = true;
            report << '"' << p.first << "\":" << p.second;
        }
        const auto& fs = fragments.stats();
        report << "},\"ip_reassembly\":{\"fragments\":" << fs.fragments << ",\"completed\":" << fs.completed
               << ",\"incomplete\":" << fs.incomplete << ",\"expired\":" << fs.expired
               << ",\"overlaps\":" << fs.overlaps << ",\"duplicates\":" << fs.duplicates
               << ",\"rejected\":" << fs.rejected << ",\"evicted\":" << fs.evicted
               << ",\"limited\":" << fs.limited << "},\"capture_format\":\"" << (captureInfo.pcapng ? "pcapng" : "pcap")
               << "\",\"interfaces\":" << captureInfo.interfaces << ",\"sections\":" << captureInfo.sections
               << ",\"skipped_blocks\":" << captureInfo.skippedBlocks << "}";
        if (!outPath.empty()) {
            std::ofstream out(outPath);
            if (!out)
                throw std::runtime_error("Cannot create JSON output");
            out << "{\"summary\":" << report.str() << ",\"packets\":[\n"
                << records.str() << "\n],\"streams\":[";
            bool c = false;
            for (const auto& entry : flows.all()) {
                const auto& f = *entry.second;
                if (c)
                    out << ',';
                c = true;
                out << "{\"id\":" << f.id << ",\"a\":\"" << fl::endpoint(f.a, f.portA) << "\",\"b\":\""
                    << fl::endpoint(f.b, f.portB) << "\",\"application\":\"" << f.application
                    << "\",\"direction_a\":\"" << fl::jsonEscape(f.directions[0].text())
                    << "\",\"direction_b\":\"" << fl::jsonEscape(f.directions[1].text())
                    << "\",\"http_analysis\":\"" << fl::jsonEscape(f.httpAnalysis()) << "\"}";
            }
            out << "]}\n";
            if (!out)
                throw std::runtime_error("JSON output failed");
        }
        std::cout << report.str() << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FlowLens: " << e.what() << "\n";
        return 1;
    }
}
