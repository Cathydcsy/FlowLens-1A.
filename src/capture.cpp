#include "flowlens/capture.hpp"
#include <winsock2.h>
#include <windows.h>
#include <chrono>
#include <stdexcept>

namespace fl {
namespace {
// Minimal public libpcap ABI. Runtime loading avoids bundling the proprietary driver.
struct pcap;
struct pcap_if {
    pcap_if* next;
    char* name;
    char* description;
    void* addresses;
    unsigned flags;
};
struct pcap_header {
    timeval ts;
    unsigned caplen;
    unsigned len;
};
struct bpf_program {
    unsigned length;
    void* instructions;
};
struct pcap_stats_t {
    unsigned received, dropped, interfaceDropped;
};
} // namespace
struct Capture::Api {
    HMODULE dll = nullptr;
    pcap* handle = nullptr;
    int link = 1;
    int (*findall)(pcap_if**, char*) = nullptr;
    void (*freeall)(pcap_if*) = nullptr;
    pcap* (*open)(const char*, int, int, int, char*) = nullptr;
    void (*close)(pcap*) = nullptr;
    int (*next)(pcap*, pcap_header**, const unsigned char**) = nullptr;
    int (*compile)(pcap*, bpf_program*, const char*, int, unsigned) = nullptr;
    int (*setfilter)(pcap*, bpf_program*) = nullptr;
    void (*freecode)(bpf_program*) = nullptr;
    int (*datalink)(pcap*) = nullptr;
    int (*setnonblock)(pcap*, int, char*) = nullptr;
    int (*stats)(pcap*, pcap_stats_t*) = nullptr;
    char* (*geterr)(pcap*) = nullptr;
    template <class T> void symbol(T& target, const char* name) {
        target = reinterpret_cast<T>(GetProcAddress(dll, name));
        if (!target)
            throw std::runtime_error(std::string("Npcap API missing: ") + name);
    }
    ~Api() {
        if (handle && close)
            close(handle);
        if (dll)
            FreeLibrary(dll);
    }
};
Capture::Capture() : api_(std::make_unique<Api>()) {
    wchar_t system[MAX_PATH]{};
    GetSystemDirectoryW(system, MAX_PATH);
    std::wstring path = std::wstring(system) + L"\\Npcap\\wpcap.dll";
    api_->dll = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!api_->dll) {
        error_ = "Npcap is not installed. Install Npcap from https://npcap.com/ and restart FlowLens. "
                 "Offline PCAP analysis remains available.";
        return;
    }
    try {
        api_->symbol(api_->findall, "pcap_findalldevs");
        api_->symbol(api_->freeall, "pcap_freealldevs");
        api_->symbol(api_->open, "pcap_open_live");
        api_->symbol(api_->close, "pcap_close");
        api_->symbol(api_->next, "pcap_next_ex");
        api_->symbol(api_->compile, "pcap_compile");
        api_->symbol(api_->setfilter, "pcap_setfilter");
        api_->symbol(api_->freecode, "pcap_freecode");
        api_->symbol(api_->datalink, "pcap_datalink");
        api_->symbol(api_->setnonblock, "pcap_setnonblock");
        api_->symbol(api_->stats, "pcap_stats");
        api_->symbol(api_->geterr, "pcap_geterr");
    } catch (const std::exception& e) {
        error_ = e.what();
        FreeLibrary(api_->dll);
        api_->dll = nullptr;
    }
}
Capture::~Capture() {
    stop();
}
bool Capture::available() const {
    return api_->dll != nullptr;
}
std::string Capture::error() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return error_;
}
std::vector<Adapter> Capture::adapters() {
    std::vector<Adapter> result;
    if (!available())
        return result;
    char error[256]{};
    pcap_if* all = nullptr;
    if (api_->findall(&all, error) != 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        error_ = error;
        return result;
    }
    for (auto* p = all; p; p = p->next)
        if (p->name)
            result.push_back({p->name, p->description ? p->description : p->name});
    api_->freeall(all);
    return result;
}
bool Capture::start(const std::string& name, const std::string& bpf) {
    stop();
    if (!available())
        return false;
    char message[256]{};
    api_->handle = api_->open(name.c_str(), 65535, 1, 100, message);
    auto fail = [&](const std::string& text) {
        std::lock_guard<std::mutex> lock(mutex_);
        error_ = text;
        if (api_->handle) {
            api_->close(api_->handle);
            api_->handle = nullptr;
        }
        return false;
    };
    if (!api_->handle)
        return fail(message);
    if (!bpf.empty()) {
        bpf_program program{};
        if (api_->compile(api_->handle, &program, bpf.c_str(), 1, 0xffffffff) != 0)
            return fail(api_->geterr(api_->handle));
        int code = api_->setfilter(api_->handle, &program);
        api_->freecode(&program);
        if (code != 0)
            return fail(api_->geterr(api_->handle));
    }
    if (api_->setnonblock(api_->handle, 1, message) != 0)
        return fail(message);
    api_->link = api_->datalink(api_->handle);
    if (api_->link < 0)
        return fail("Cannot determine capture link type");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_ = {};
        queue_.clear();
        queuedBytes_ = 0;
        error_.clear();
    }
    running_ = true;
    worker_ = std::thread([this] {
        auto last = std::chrono::steady_clock::now();
        while (running_) {
            pcap_header* header = nullptr;
            const unsigned char* data = nullptr;
            int code = api_->next(api_->handle, &header, &data);
            if (code == 1 && header && data) {
                if (header->caplen > 16 * 1024 * 1024 || header->caplen > header->len) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    error_ = "Invalid captured packet length";
                    running_ = false;
                    break;
                }
                Packet p;
                p.checksumMode = ChecksumMode::OffloadPossible;
                p.timestampNs =
                    uint64_t(header->ts.tv_sec) * 1000000000ULL + uint64_t(header->ts.tv_usec) * 1000;
                p.originalLength = header->len;
                p.linkType = uint32_t(api_->link);
                p.bytes.assign(data, data + header->caplen);
                std::lock_guard<std::mutex> lock(mutex_);
                stats_.received++;
                if (queue_.size() < 5000 && queuedBytes_ + p.bytes.size() <= 16 * 1024 * 1024) {
                    queuedBytes_ += p.bytes.size();
                    queue_.push_back(std::move(p));
                } else
                    stats_.queueDropped++;
            } else if (code < 0) {
                std::lock_guard<std::mutex> lock(mutex_);
                if (code == -1)
                    error_ = api_->geterr(api_->handle);
                running_ = false;
                break;
            } else
                std::this_thread::sleep_for(std::chrono::milliseconds(4));
            auto now = std::chrono::steady_clock::now();
            if (now - last > std::chrono::seconds(1)) {
                pcap_stats_t s{};
                int ok = api_->stats(api_->handle, &s);
                std::lock_guard<std::mutex> lock(mutex_);
                stats_.driverStatsAvailable = ok == 0;
                if (ok == 0)
                    stats_.driverDropped = s.dropped;
                last = now;
            }
        }
    });
    return true;
}
void Capture::stop() {
    running_ = false;
    if (worker_.joinable())
        worker_.join();
    if (api_->handle) {
        api_->close(api_->handle);
        api_->handle = nullptr;
    }
}
std::vector<Packet> Capture::take(size_t maximum) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Packet> result;
    while (!queue_.empty() && result.size() < maximum) {
        queuedBytes_ -= queue_.front().bytes.size();
        result.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    return result;
}
CaptureStats Capture::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}
} // namespace fl
