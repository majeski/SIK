#include <boost/bind.hpp>

#include "TCPService.h"
#include "settings.h"

TCPService::TCPService(boost::asio::io_service &ioService, LatencyDatabase &latencyDatabase)
    : ioService(ioService), latencyDatabase(latencyDatabase) {
}

void TCPService::measureLatency(const std::vector<boost::asio::ip::address_v4> &addrs) {
    refreshHistory();
    for (auto addr : addrs) {
        asyncConnect(addr);
    }
}

void TCPService::asyncConnect(boost::asio::ip::address_v4 addr) {
    static const u16 port = TCP_PORT;

    auto socket = std::make_shared<socket_t>(ioService);

    auto curTime = std::chrono::system_clock::now();
    history.push(std::make_pair(socket, curTime));

    socket->async_connect(boost::asio::ip::tcp::endpoint(addr, port),
                          boost::bind(&TCPService::handleConnect,
                                      this,
                                      socket,
                                      curTime,
                                      addr,
                                      boost::asio::placeholders::error));
}

void TCPService::refreshHistory() {
    static const std::chrono::seconds maxLatency(MAX_LATENCY_SECS);
    auto curTime = std::chrono::system_clock::now();

    while (!history.empty() && curTime - maxLatency > history.front().second) {
        auto socket = history.front().first.lock();
        if (socket) {
            socket->cancel();
        }
        history.pop();
    }
}

void TCPService::handleConnect(std::shared_ptr<socket_t> socket,
                               std::chrono::system_clock::time_point sendTime,
                               boost::asio::ip::address_v4 remoteAddr,
                               const boost::system::error_code &error) {
    if (error) {
        return;
    }

    auto curTime = std::chrono::system_clock::now();
    LatencyDatabase::latency_t latency =
        std::chrono::duration_cast<std::chrono::microseconds>(curTime - sendTime);
    latencyDatabase.addLatency(LatencyDatabase::ProtocolType::TCP, remoteAddr, latency);
}