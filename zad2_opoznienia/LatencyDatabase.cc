#include <algorithm>

#include "LatencyDatabase.h"

const std::vector<LatencyDatabase::ProtocolType> LatencyDatabase::allProtocols = {
    ProtocolType::UDP, ProtocolType::TCP, ProtocolType::ICMP};

void LatencyDatabase::setConnectionAvailable(LatencyDatabase::ProtocolType protocol, addr_t addr,
                                             std::chrono::seconds ttl) {
    std::unique_lock<std::mutex>(dataMutex);
    auto &host = data[addr];

    host.updateExpired();
    if (!host.isAnyProtocolAvailable()) {
        host = Host();
    }

    if (protocol == ProtocolType::TCP) {
        host.setTCPExpiration(std::chrono::system_clock::now() + ttl);
    }
    if (protocol == ProtocolType::UDP) {
        host.setUDPExpiration(std::chrono::system_clock::now() + ttl);
    }
}

void LatencyDatabase::addLatency(LatencyDatabase::ProtocolType protocol, addr_t addr,
                                 latency_t ms) {
    std::unique_lock<std::mutex>(dataMutex);

    auto &host = data[addr];
    host.updateExpired();
    if (!host.isAnyProtocolAvailable()) {
        data.erase(addr);
        return;
    }

    if (!host.isProtocolAvailable(protocol)) {
        return;
    }

    host.addLatency(protocol, ms);
}

std::vector<std::pair<LatencyDatabase::addr_t, LatencyDatabase::Host>> LatencyDatabase::getAll() {
    std::unique_lock<std::mutex>(dataMutex);

    std::vector<std::pair<addr_t, Host>> res;
    auto it = data.begin();
    while (it != data.end()) {
        it->second.updateExpired();
        if (!it->second.isAnyProtocolAvailable()) {
            it = data.erase(it);
        } else {
            res.push_back(*it);
            ++it;
        }
    }
    return res;
}

LatencyDatabase::Host::Host()
    : tcpExpiration(time_point_t::min()),
      udpExpiration(time_point_t::min()),
      udpExpired(true),
      tcpExpired(true) {
}

void LatencyDatabase::Host::addLatency(LatencyDatabase::ProtocolType protocol, latency_t ms) {
    TimeMemory *tMem = getForProtocol(protocol);

    tMem->lastIdx = (tMem->lastIdx + 1) % 10;
    tMem->count = std::min(tMem->count + 1, 10u);

    tMem->sum -= tMem->latencies[tMem->lastIdx];
    tMem->latencies[tMem->lastIdx] = ms;
    tMem->sum += ms;

    updateExpired();
}

void LatencyDatabase::Host::setTCPExpiration(time_point_t expiration) {
    tcpExpiration = expiration;
    updateExpired();
}

void LatencyDatabase::Host::setUDPExpiration(time_point_t expiration) {
    udpExpiration = expiration;
    updateExpired();
}

void LatencyDatabase::Host::updateExpired() {
    auto timeNow = std::chrono::system_clock::now();
    udpExpired = false;
    tcpExpired = false;

    if (timeNow > tcpExpiration) {
        tcpTime = TimeMemory();
        tcpExpired = true;
    } else {
        tcpExpired = false;
    }

    if (timeNow > udpExpiration) {
        udpTime = TimeMemory();
        icmpTime = TimeMemory();
        udpExpired = true;
    } else {
        udpExpired = false;
    }
}

bool LatencyDatabase::Host::isAnyProtocolAvailable() const {
    return !tcpExpired || !udpExpired;
}

bool LatencyDatabase::Host::isProtocolAvailable(LatencyDatabase::ProtocolType protocol) const {
    if (protocol == LatencyDatabase::ProtocolType::TCP) {
        return !tcpExpired;
    }
    return !udpExpired;
}

bool LatencyDatabase::Host::isAnyLatencyKnown() const {
    for (const auto protocol : LatencyDatabase::allProtocols) {
        if (isLatencyKnown(protocol)) {
            return true;
        }
    }
    return false;
}

double LatencyDatabase::Host::getAverageLatency() const {
    u32 sum = 0;
    u8 count = 0;
    for (const auto protocol : LatencyDatabase::allProtocols) {
        if (isLatencyKnown(protocol)) {
            sum += getLatency(protocol).count();
            count++;
        }
    }

    return count ? (double)sum / count : std::numeric_limits<double>::max();
}

bool LatencyDatabase::Host::isLatencyKnown(LatencyDatabase::ProtocolType protocol) const {
    return getForProtocolConst(protocol)->count;
}

LatencyDatabase::latency_t LatencyDatabase::Host::getLatency(
    LatencyDatabase::ProtocolType protocol) const {
    const TimeMemory *tMem = getForProtocolConst(protocol);
    if (tMem->count) {
        return tMem->sum / tMem->count;
    } else {
        throw std::logic_error("Latency not available/not known");
    }
}

const LatencyDatabase::Host::TimeMemory *LatencyDatabase::Host::getForProtocolConst(
    LatencyDatabase::ProtocolType protocol) const {
    switch (protocol) {
        case ProtocolType::ICMP:
            return &icmpTime;
        case ProtocolType::UDP:
            return &udpTime;
        case ProtocolType::TCP:
            return &tcpTime;
    }
    return nullptr;
}

LatencyDatabase::Host::TimeMemory *LatencyDatabase::Host::getForProtocol(
    LatencyDatabase::ProtocolType protocol) {
    switch (protocol) {
        case ProtocolType::ICMP:
            return &icmpTime;
        case ProtocolType::UDP:
            return &udpTime;
        case ProtocolType::TCP:
            return &tcpTime;
    }
    return nullptr;
}

LatencyDatabase::Host::TimeMemory::TimeMemory() : lastIdx(0), count(0), sum(0) {
    for (auto &x : latencies) {
        x = latency_t(0);
    }
}
