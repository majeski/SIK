#ifndef ICMP_SERVICE__H
#define ICMP_SERVICE__H

#include <thread>
#include <queue>
#include <map>

#include "ICMPEchoPacket.h"
#include "LatencyDatabase.h"

class ICMPService {
public:
    ICMPService(boost::asio::io_service &ioServiceForListening, LatencyDatabase &latencyDatabase);
    ICMPService() = default;
    ICMPService(const ICMPService &) = delete;
    ICMPService(ICMPService &&) = delete;
    ICMPService &operator=(const ICMPService &) = delete;
    ICMPService &operator=(ICMPService &&) = delete;

    // receive asynchronously, handlers on ioServiceForListening threads
    void startListening();

    // send requests synchronously on caller thread
    void measureLatency(const std::vector<boost::asio::ip::address_v4> &addrs);

private:
    struct HistoryEntry {
        u32 peerAddr;
        u16 identifier;
        u16 seqNumber;

        bool operator<(const HistoryEntry &that) const;
    };
    u16 curSeqNum;
    u32 requestData;
    std::queue<std::pair<HistoryEntry, std::chrono::system_clock::time_point>> requestHistory;
    std::map<HistoryEntry, std::chrono::system_clock::time_point> requestTime;
    std::mutex historyMutex;

    bool listening;
    std::vector<u8> buffer;
    LatencyDatabase &latencyDatabase;

    std::mutex socketMutex;
    boost::asio::ip::icmp::socket socket;
    boost::asio::ip::icmp::endpoint senderEndpoint;

    void asyncReceive();

    void handleMessage(const boost::system::error_code &error, std::size_t bytesToRead);
    void handleICMPMessage(const ICMPEchoPacket &packet,
                           std::chrono::system_clock::time_point receiveTime,
                           boost::asio::ip::address_v4 senderAddr);
    void sendRequest(const boost::asio::ip::address_v4 &addr);
    void refreshHistory();
    void prepareRequestData();
};

#endif