#include <boost/bind.hpp>

#include "UDPService.h"
#include "settings.h"

UDPService::UDPService(boost::asio::io_service &ioServiceForListening,
                       LatencyDatabase &latencyDatabase, u16 serverPort)
    : port(serverPort),
      listening(false),
      clientSocket(ioServiceForListening),
      serverSocket(ioServiceForListening),
      clientBuffer(BUFFER_SIZE),
      serverBuffer(BUFFER_SIZE),
      latencyDatabase(latencyDatabase) {
}

void UDPService::startListening() {
    if (!listening) {
        prepareSockets();
        asyncServerReceive();
        asyncClientReceive();
        listening = true;
    } else {
        throw std::logic_error("already running");
    }
}

void UDPService::prepareSockets() {
    using namespace boost::asio;
    clientSocket.open(ip::udp::v4());
    serverSocket.open(ip::udp::v4());
    serverSocket.bind(ip::udp::endpoint(ip::udp::v4(), port));
}

void UDPService::asyncServerReceive() {
    serverSocket.async_receive_from(boost::asio::buffer(serverBuffer),
                                    serverSocketSenderEndpoint,
                                    boost::bind(&UDPService::handleServerInput,
                                                this,
                                                boost::asio::placeholders::error,
                                                boost::asio::placeholders::bytes_transferred));
}

void UDPService::handleServerInput(const boost::system::error_code &error, std::size_t bytesCount) {
    if (!error && bytesCount == sizeof(u64)) {
        Message msg(serverBuffer);
        msg.responseTime = getCurTime();

        boost::system::error_code ec;
        serverSocket.send_to(boost::asio::buffer(msg.generateNetworkFormat()),
                             serverSocketSenderEndpoint,
                             boost::asio::ip::udp::socket::message_flags(),
                             ec);
    }
    asyncServerReceive();
}

void UDPService::asyncClientReceive() {
    clientSocketMutex.lock();
    clientSocket.async_receive_from(boost::asio::buffer(clientBuffer),
                                    clientSocketSenderEndpoint,
                                    boost::bind(&UDPService::handleClientInput,
                                                this,
                                                boost::asio::placeholders::error,
                                                boost::asio::placeholders::bytes_transferred));
    clientSocketMutex.unlock();
}

void UDPService::handleClientInput(const boost::system::error_code &error, std::size_t bytesCount) {
    if (!error && bytesCount == 2 * sizeof(u64)) {
        handleClientResponse(clientSocketSenderEndpoint.address().to_v4());
    }
    asyncClientReceive();
}

void UDPService::handleClientResponse(const boost::asio::ip::address_v4 &senderAddr) {
    Message msg(clientBuffer);
    u64 curTime = getCurTime();
    HistoryEntry request{bitops::addrToU32(senderAddr), msg.sendTime};

    historyMutex.lock();
    refreshHistory();
    if (requests.find(request) != requests.end()) {
        LatencyDatabase::latency_t latency = std::chrono::microseconds(curTime - request.sendTime);
        requests.erase(request);
        historyMutex.unlock();

        latencyDatabase.addLatency(LatencyDatabase::ProtocolType::UDP, senderAddr, latency);
    } else {
        historyMutex.unlock();
    }
}

void UDPService::refreshHistory() {
    static const u64 maxLatency = std::chrono::duration_cast<std::chrono::microseconds>(
                                      std::chrono::seconds(MAX_LATENCY_SECS))
                                      .count();

    u64 curTime = getCurTime();
    while (!requestHistory.empty() && requestHistory.front().sendTime < curTime - maxLatency) {
        if (requests.find(requestHistory.front()) != requests.end()) {
            requests.erase(requestHistory.front());
        }
        requestHistory.pop();
    }
}

void UDPService::measureLatency(const std::vector<boost::asio::ip::address_v4> &addrs) {
    for (auto addr : addrs) {
        historyMutex.lock();

        u64 curTime = getCurTime();
        std::vector<u8> request = bitops::divide(curTime);
        HistoryEntry hEntry{bitops::addrToU32(addr), curTime};
        requestHistory.push(hEntry);
        requests.insert(hEntry);

        historyMutex.unlock();

        boost::system::error_code ec;
        clientSocketMutex.lock();
        clientSocket.send_to(boost::asio::buffer(request),
                             boost::asio::ip::udp::endpoint(addr, port),
                             boost::asio::ip::udp::socket::message_flags(),
                             ec);
        clientSocketMutex.unlock();
    }
}

bool UDPService::HistoryEntry::operator<(const UDPService::HistoryEntry &that) const {
    return std::make_pair(peerAddr, sendTime) < std::make_pair(that.peerAddr, that.sendTime);
}

UDPService::Message::Message(const std::vector<u8> &rawData) {
    auto it = rawData.begin();
    sendTime = bitops::getU64(it, rawData.end());
    responseTime = 0;
}

std::vector<u8> UDPService::Message::generateNetworkFormat() const {
    std::vector<u8> res;
    bitops::addTo(res, sendTime);
    bitops::addTo(res, responseTime);
    return res;
}

u64 UDPService::getCurTime() const {
    auto curTimePoint = std::chrono::system_clock::now();
    u64 res = std::chrono::duration_cast<std::chrono::microseconds>(curTimePoint.time_since_epoch())
                  .count();
    return res;
}
