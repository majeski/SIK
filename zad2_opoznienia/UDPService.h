#ifndef UDP_SERVICE__H
#define UDP_SERVICE__H

#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <chrono>
#include <boost/asio.hpp>

#include "LatencyDatabase.h"
#include "bitops.h"

class UDPService {
public:
    UDPService(boost::asio::io_service &ioServiceForListening, LatencyDatabase &latencyDatabase,
               u16 serverPort);
    UDPService() = default;
    UDPService(const UDPService &) = delete;
    UDPService(UDPService &&) = delete;
    UDPService &operator=(const UDPService &) = delete;
    UDPService &operator=(UDPService &&) = delete;

    void startListening();

    // send requests synchronously on caller thread
    // calls from several threads at the same time are prohibited
    void measureLatency(const std::vector<boost::asio::ip::address_v4> &addrs);

private:
    struct HistoryEntry {
        u32 peerAddr;
        u64 sendTime;

        bool operator<(const HistoryEntry &that) const;
    };

    struct Message {
        u64 sendTime;
        u64 responseTime;

        Message() = default;
        Message(const std::vector<u8> &rawRequest);
        std::vector<u8> generateNetworkFormat() const;
    };

    u16 port;
    bool listening;

    boost::asio::ip::udp::socket clientSocket;
    boost::asio::ip::udp::socket serverSocket;

    std::mutex clientSocketMutex;

    boost::asio::ip::udp::endpoint clientSocketSenderEndpoint;
    boost::asio::ip::udp::endpoint serverSocketSenderEndpoint;
    std::vector<u8> clientBuffer;
    std::vector<u8> serverBuffer;

    LatencyDatabase &latencyDatabase;

    std::queue<HistoryEntry> requestHistory;
    std::set<HistoryEntry> requests;
    std::mutex historyMutex;

    void prepareSockets();

    void asyncServerReceive();
    void asyncClientReceive();

    void handleServerInput(const boost::system::error_code &error, std::size_t bytesCount);
    void handleClientInput(const boost::system::error_code &error, std::size_t bytesCount);
    void handleClientResponse(const boost::asio::ip::address_v4 &senderAddr);

    void refreshHistory();
    u64 getCurTime() const;
};

#endif