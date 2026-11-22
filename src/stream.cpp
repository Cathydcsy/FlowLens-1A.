#include "flowlens/stream.hpp"
#include <algorithm>
#include <limits>
#include <sstream>

namespace fl {
void DirectionStream::establish(uint32_t seq, bool syn) {
    if (!hasBase) {
        base = seq;
        hasBase = true;
        fromSyn = syn;
    }
}
void DirectionStream::insert(uint32_t seq, const uint8_t* data, size_t n) {
    if (!n)
        return;
    establish(seq, false);
    int64_t start = static_cast<int32_t>(seq - base), end = start + int64_t(n);
    if (n > limit || start > int64_t(limit) || end < -int64_t(limit) || end - start > int64_t(limit)) {
        limited = true;
        return;
    }
    int64_t expected = 0;
    auto first = chunks.begin();
    if (first != chunks.end() && first->first <= 0)
        expected = first->first + int64_t(first->second.size());
    if (start > expected)
        outOfOrder++;
    auto begin = chunks.lower_bound(start);
    if (begin != chunks.begin()) {
        auto prev = std::prev(begin);
        if (prev->first + int64_t(prev->second.size()) >= start)
            begin = prev;
    }
    auto stop = begin;
    int64_t lo = start, hi = end;
    size_t oldSize = 0;
    while (stop != chunks.end() && stop->first <= hi) {
        if (stop->first + int64_t(stop->second.size()) < lo) {
            ++stop;
            begin = stop;
            continue;
        }
        lo = std::min(lo, stop->first);
        hi = std::max(hi, stop->first + int64_t(stop->second.size()));
        oldSize += stop->second.size();
        ++stop;
    }
    if (hi - lo > int64_t(limit) || buffered - oldSize + size_t(hi - lo) > limit || chunks.size() > 2048) {
        limited = true;
        return;
    }
    std::vector<uint8_t> merged(size_t(hi - lo), 0);
    std::copy(data, data + n, merged.begin() + size_t(start - lo));
    for (auto it = begin; it != stop; ++it) {
        int64_t overlapStart = std::max(start, it->first),
                overlapEnd = std::min(end, it->first + int64_t(it->second.size()));
        if (overlapEnd > overlapStart) {
            retransmitted += size_t(overlapEnd - overlapStart);
            for (int64_t i = overlapStart; i < overlapEnd; i++)
                if (data[size_t(i - start)] != it->second[size_t(i - it->first)])
                    conflicts++;
        }
        // 冲突重传时保留首次出现的字节，并统计冲突次数。
        std::copy(it->second.begin(), it->second.end(), merged.begin() + size_t(it->first - lo));
    }
    chunks.erase(begin, stop);
    buffered = buffered - oldSize + merged.size();
    chunks.emplace(lo, std::move(merged));
}
std::vector<uint8_t> DirectionStream::contiguous() const {
    if (chunks.empty())
        return {};
    if (fromSyn && chunks.begin()->first > 0)
        return {};
    return chunks.begin()->second;
}
size_t DirectionStream::gaps() const {
    if (chunks.empty())
        return 0;
    return chunks.size() - 1 + size_t(fromSyn && chunks.begin()->first > 0);
}
std::string DirectionStream::text() const {
    std::ostringstream o;
    if (!fromSyn)
        o << "[Capture started without SYN; leading data may be missing]\n";
    int64_t next = fromSyn ? 0 : (chunks.empty() ? 0 : chunks.begin()->first);
    for (const auto& chunk : chunks) {
        if (chunk.first > next)
            o << "\n[Missing " << chunk.first - next << " bytes]\n";
        o << printable(chunk.second);
        next = chunk.first + int64_t(chunk.second.size());
    }
    if (limited)
        o << "\n[Reassembly buffer limit reached; stream is partial]\n";
    return o.str();
}
std::string Flow::httpAnalysis() const {
    std::ostringstream o;
    for (int i = 0; i < 2; i++) {
        auto data = directions[i].contiguous();
        if (!identifyHttp(data).empty())
            o << (i == 0 ? "A -> B\n" : "B -> A\n") << inspectHttp(data) << "\n";
    }
    return o.str();
}
size_t FlowTable::buffered() const {
    size_t n = 0;
    for (const auto& f : flows_)
        n += f.second->directions[0].buffered + f.second->directions[1].buffered;
    return n;
}
std::shared_ptr<Flow> FlowTable::get(uint64_t id) const {
    auto it = flows_.find(id);
    return it == flows_.end() ? nullptr : it->second;
}
bool FlowTable::syncProcessOwners(Packet& p) const {
    auto f = get(p.flowId);
    if (!f || p.transport != 6 || p.interfaceId != f->interfaceId || p.sectionId != f->sectionId)
        return false;
    const bool forward = p.source == f->a && p.destination == f->b &&
                         p.sourcePort == f->portA && p.destinationPort == f->portB;
    const bool reverse = p.source == f->b && p.destination == f->a &&
                         p.sourcePort == f->portB && p.destinationPort == f->portA;
    if (!forward && !reverse)
        return false;
    bool changed = p.flowProcesses != f->owners;
    if (changed) p.flowProcesses = f->owners;
    if (p.reassembled)
        changed = syncProcessOwners(*p.reassembled) || changed;
    return changed;
}
std::shared_ptr<Flow> FlowTable::ingest(Packet& p) {
    if (p.reassembled) {
        auto& logical = *p.reassembled;
        logical.pid = p.pid; logical.peerPid = p.peerPid;
        logical.process = p.process; logical.peerProcess = p.peerProcess;
        auto flow = ingest(logical);
        p.flowId = logical.flowId; p.protocol = logical.protocol; p.httpHost = logical.httpHost;
        p.flowProcesses = logical.flowProcesses;
        return flow;
    }
    if (p.transport != 6 || p.fragmented || p.payloadOffset == 0)
        return nullptr;
    std::string src = endpoint(p.source, p.sourcePort), dst = endpoint(p.destination, p.destinationPort);
    bool reverse = src > dst;
    std::string key = std::to_string(p.sectionId) + "/" + std::to_string(p.interfaceId) + "/" +
        std::to_string(p.ipVersion) + "/" + (reverse ? dst + "/" + src : src + "/" + dst);
    auto it = active_.find(key);
    std::shared_ptr<Flow> f = it == active_.end() ? nullptr : get(it->second);
    bool syn = (p.tcpFlags & 2) != 0, initialSyn = syn && !(p.tcpFlags & 16);
    bool timeout = f && p.timestampNs > f->lastNs && p.timestampNs - f->lastNs > 120000000000ULL;
    bool newSession =
        f && initialSyn &&
        (f->closed || (f->hasSyn && (f->synSequence != p.sequence || f->synReverse != reverse)));
    if (!f || timeout || newSession) {
        if (flows_.size() >= maxFlows) {
            auto oldest = std::min_element(flows_.begin(), flows_.end(), [](const auto& a, const auto& b) {
                return a.second->lastNs < b.second->lastNs;
            });
            uint64_t gone = oldest->first;
            flows_.erase(oldest);
            for (auto ai = active_.begin(); ai != active_.end();)
                if (ai->second == gone)
                    ai = active_.erase(ai);
                else
                    ++ai;
            evicted++;
        }
        f = std::make_shared<Flow>();
        f->id = nextId_++;
        f->firstNs = p.timestampNs;
        f->interfaceId = p.interfaceId;
        f->sectionId = p.sectionId;
        f->a = reverse ? p.destination : p.source;
        f->b = reverse ? p.source : p.destination;
        f->portA = reverse ? p.destinationPort : p.sourcePort;
        f->portB = reverse ? p.sourcePort : p.destinationPort;
        flows_[f->id] = f;
        active_[key] = f->id;
    }
    if (initialSyn) {
        f->hasSyn = true;
        f->synSequence = p.sequence;
        f->synReverse = reverse;
    }
    p.flowId = f->id;
    f->packets++;
    f->bytes += p.originalLength;
    f->lastNs = std::max(f->lastNs, p.timestampNs);
    if (p.pid) {
        f->owners[p.pid] = p.process;
        if (!f->pid) {
            f->pid = p.pid;
            f->process = p.process;
        }
    }
    if (p.peerPid)
        f->owners[p.peerPid] = p.peerProcess;
    p.flowProcesses = f->owners;
    if (p.tcpFlags & 4)
        f->closed = true;
    if (p.tcpFlags & 1) {
        f->finMask |= 1u << unsigned(reverse);
        if (f->finMask == 3)
            f->closed = true;
    }
    auto& direction = f->directions[reverse ? 1 : 0];
    direction.establish(p.sequence + uint32_t(syn), syn);
    if (p.payloadLength) {
        if (buffered() + p.payloadLength <= globalBufferLimit)
            direction.insert(p.sequence + uint32_t(syn), p.bytes.data() + p.payloadOffset, p.payloadLength);
        else
            direction.limited = true;
    }
    if (p.protocol == "HTTP" || p.protocol == "TLS" || p.protocol == "DNS")
        f->application = p.protocol;
    std::string host;
    auto data = direction.contiguous();
    auto line = identifyHttp(data, &host);
    if (!line.empty()) {
        f->application = "HTTP";
        p.httpHost = host;
        if (p.protocol == "TCP" && p.payloadLength) {
            p.protocol = "HTTP";
            p.info = line + " [reassembled]";
        }
    }
    if (f->application == "HTTP" && p.payloadLength)
        p.protocol = "HTTP";
    if (f->events.size() < 1000)
        f->events.push_back({p.id, p.timestampNs, reverse, tcpFlags(p.tcpFlags), p.payloadLength});
    return f;
}
void FlowTable::clear() {
    active_.clear();
    flows_.clear();
    nextId_ = 1;
    evicted = 0;
}
} // namespace fl
