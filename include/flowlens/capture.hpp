#pragma once
#include "packet.hpp"
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

namespace fl {
struct Adapter {
    std::string name, description;
};
struct CaptureStats {
    uint64_t received = 0, queueDropped = 0, driverDropped = 0;
    bool driverStatsAvailable = false;
};
class Capture {
    struct Api;
    std::unique_ptr<Api> api_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    std::deque<Packet> queue_;
    size_t queuedBytes_ = 0;
    std::string error_;
    CaptureStats stats_;

  public:
    Capture();
    ~Capture();
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
    bool available() const;
    std::string error() const;
    std::vector<Adapter> adapters();
    bool start(const std::string& name, const std::string& bpf);
    void stop();
    bool running() const {
        return running_.load();
    }
    std::vector<Packet> take(size_t maximum = 1000);
    CaptureStats stats() const;
};
} // namespace fl
