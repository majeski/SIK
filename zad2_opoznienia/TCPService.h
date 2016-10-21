#ifndef TCP_SERVICE__H
#define TCP_SERVICE__H

#include <chrono>
#include <map>
#include <queue>
#include <boost/asio.hpp>

#include "LatencyDatabase.h"
#include "bitops.h"

class TCPService {
public:
    TCPService(boost::asio::io_service &ioService, LatencyDatabase &lb);
    TCPService() = default;
    TCPService(const TCPService &) = delete;
    TCPService(TCPService &&) = delete;
    TCPService &operator=(const TCPService &) = delete;
    TCPService &operator=(TCPService &&) = delete;

    // calls from several threads at the same time are prohibited
    void measureLatency(const std::vector<boost::asio::ip::address_v4> &addrs);

private:
    using socket_t = boost::asio::ip::tcp::socket;

    std::queue<std::pair<std::weak_ptr<socket_t>, std::chrono::system_clock::time_point>> history;

    boost::asio::io_service &ioService;
    LatencyDatabase &latencyDatabase;

    void refreshHistory();
    void asyncConnect(boost::asio::ip::address_v4 addr);
    void handleConnect(std::shared_ptr<socket_t> socket,
                       std::chrono::system_clock::time_point sendTime,
                       boost::asio::ip::address_v4 remoteAddr,
                       const boost::system::error_code &error);
};

#endif