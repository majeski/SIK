#ifndef LATENCY_DATABASE__H
#define LATENCY_DATABASE__H

#include <chrono>
#include <mutex>
#include <boost/asio.hpp>

#include "bitops.h"

class LatencyDatabase {
public:
    using addr_t = boost::asio::ip::address_v4;
    using latency_t = std::chrono::microseconds;
    enum class ProtocolType { ICMP, TCP, UDP };

    // order: UDP, TCP, ICMP
    static const std::vector<ProtocolType> allProtocols;

    class Host {
    public:
        using time_point_t = std::chrono::time_point<std::chrono::system_clock>;

        Host();
        latency_t getLatency(ProtocolType protocol) const;
        void addLatency(ProtocolType protocol, latency_t ms);

        void setTCPExpiration(time_point_t expiration);
        void setUDPExpiration(time_point_t expiration);

        void updateExpired();

        bool isProtocolAvailable(ProtocolType protocol) const;
        bool isAnyProtocolAvailable() const;

        bool isLatencyKnown(ProtocolType protocol) const;
        bool isAnyLatencyKnown() const;
        double getAverageLatency() const;

    private:
        struct TimeMemory {
            TimeMemory();

            unsigned lastIdx;
            unsigned count;
            latency_t latencies[10];
            latency_t sum;
        };

        time_point_t tcpExpiration;
        time_point_t udpExpiration;
        TimeMemory icmpTime;
        TimeMemory tcpTime;
        TimeMemory udpTime;
        bool udpExpired;
        bool tcpExpired;

        TimeMemory *getForProtocol(ProtocolType protocol);
        const TimeMemory *getForProtocolConst(ProtocolType protocol) const;
    };

    // thread-safe
    void setConnectionAvailable(ProtocolType ProtocolType, addr_t addr, std::chrono::seconds ttl);

    // thread-safe
    void addLatency(ProtocolType type, addr_t addr, latency_t ms);

    // thread-safe
    // returns copy of not expired hosts
    std::vector<std::pair<addr_t, Host>> getAll();

private:
    std::map<addr_t, Host> data;
    std::mutex dataMutex;
};

#endif