#include <boost/bind.hpp>

#include "ICMPService.h"
#include "ICMPEchoPacket.h"
#include "settings.h"

ICMPService::ICMPService(boost::asio::io_service &ioServiceForListening,
                         LatencyDatabase &latencyDatabse)
    : curSeqNum(0),
      listening(false),
      buffer(BUFFER_SIZE),
      latencyDatabase(latencyDatabse),
      socket(ioServiceForListening) {
    prepareRequestData();
}

void ICMPService::prepareRequestData() {
    // 347108 = 0x054BE4
    // 3 = 0x03
    requestData = bitops::merge(0x05, 0x4B, 0xE4, 0x03);
}

void ICMPService::startListening() {
    if (!listening) {
        socket.open(boost::asio::ip::icmp::v4());
        asyncReceive();
        listening = true;
    } else {
        throw std::logic_error("already running");
    }
}

void ICMPService::asyncReceive() {
    socketMutex.lock();
    socket.async_receive_from(boost::asio::buffer(buffer),
                              senderEndpoint,
                              boost::bind(&ICMPService::handleMessage,
                                          this,
                                          boost::asio::placeholders::error,
                                          boost::asio::placeholders::bytes_transferred));
    socketMutex.unlock();
}

void ICMPService::handleMessage(const boost::system::error_code &error, std::size_t bytesToRead) {
    if (!error) {
        try {
            auto curTime = std::chrono::system_clock::now();
            auto packet = ICMPEchoPacket(buffer, bytesToRead, true);
            handleICMPMessage(packet, curTime, senderEndpoint.address().to_v4());
        } catch (UnknownFormatException &) {
        }
    }
    asyncReceive();
}

void ICMPService::handleICMPMessage(const ICMPEchoPacket &reply,
                                    std::chrono::system_clock::time_point receiveTime,
                                    boost::asio::ip::address_v4 senderAddr) {
    if (reply.type != ICMPEchoPacket::REPLY || reply.code != 0 || reply.data != requestData) {
        return;
    }
    HistoryEntry request{bitops::addrToU32(senderAddr), reply.identifier, reply.seqNumber};

    historyMutex.lock();
    if (requestTime.find(request) != requestTime.end()) {
        LatencyDatabase::latency_t latency = std::chrono::duration_cast<std::chrono::microseconds>(
            receiveTime - requestTime[request]);
        requestTime.erase(request);
        historyMutex.unlock();

        latencyDatabase.addLatency(LatencyDatabase::ProtocolType::ICMP, senderAddr, latency);
    } else {
        historyMutex.unlock();
    }
}

void ICMPService::measureLatency(const std::vector<boost::asio::ip::address_v4> &addrs) {
    historyMutex.lock();
    refreshHistory();
    historyMutex.unlock();

    for (auto addr : addrs) {
        sendRequest(addr);
    }
    curSeqNum++;
    if (curSeqNum == 0xFFFF) {
        curSeqNum = 0;
    }
}

void ICMPService::refreshHistory() {
    static const auto maxLatency = std::chrono::seconds(MAX_LATENCY_SECS);
    auto timeNow = std::chrono::system_clock::now();
    while (!requestHistory.empty() && requestHistory.front().second < timeNow - maxLatency) {
        if (requestTime.find(requestHistory.front().first) != requestTime.end()) {
            requestTime.erase(requestHistory.front().first);
        }
        requestHistory.pop();
    }
}

void ICMPService::sendRequest(const boost::asio::ip::address_v4 &addr) {
    ICMPEchoPacket request;
    request.type = ICMPEchoPacket::ICMPType::REQUEST;
    request.identifier = rand();
    request.seqNumber = curSeqNum;
    request.data = requestData;

    boost::system::error_code ec;
    socketMutex.lock();
    socket.send_to(boost::asio::buffer(request.generateNetworkFormat()),
                   boost::asio::ip::icmp::endpoint(addr, 0),
                   boost::asio::ip::icmp::socket::message_flags(),
                   ec);
    socketMutex.unlock();
    if (ec) {
        return;
    }

    auto nowTime = std::chrono::system_clock::now();
    HistoryEntry historyEntry{bitops::addrToU32(addr), request.identifier, request.seqNumber};

    historyMutex.lock();
    requestTime[historyEntry] = nowTime;
    requestHistory.push(std::make_pair(historyEntry, nowTime));
    historyMutex.unlock();
}

bool ICMPService::HistoryEntry::operator<(const HistoryEntry &that) const {
    return std::make_pair(std::make_pair(peerAddr, identifier), seqNumber) <
           std::make_pair(std::make_pair(that.peerAddr, that.identifier), that.seqNumber);
}
