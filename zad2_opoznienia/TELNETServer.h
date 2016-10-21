#ifndef TELNET_SERVER__H
#define TELNET_SERVER__H

#include <chrono>
#include <thread>
#include <mutex>
#include <list>
#include <memory>

#include <boost/asio.hpp>

#include "bitops.h"
#include "LatencyDatabase.h"

class TELNETServer {
public:
    TELNETServer(u16 port, LatencyDatabase &latencyDatabase);

    // run server in background
    void run(std::chrono::microseconds refreshTime);

private:
    static const u8 TELNET_ECHO = 1;
    static const u8 SUPPRESS_GO_AHEAD = 3;
    static const u8 BELL = 7;
    static const u8 WILL = 251;
    static const u8 WONT = 252;
    static const u8 DO = 253;
    static const u8 DONT = 254;
    static const u8 IAC = 255;

    static const u8 ESC = 27;

    static const u8 CONSOLE_HEIGHT = 24;
    static const u8 CONSOLE_WIDTH = 80;

    static bool compareHostEntry(
        const std::pair<LatencyDatabase::addr_t, LatencyDatabase::Host> &a,
        const std::pair<LatencyDatabase::addr_t, LatencyDatabase::Host> &b);

    struct TCPConnection {
        boost::asio::ip::tcp::socket socket;
        std::mutex socketMutex;
        std::vector<u8> receivedData;
        unsigned firstRowPos;
        unsigned receivedCommandsCount;

        TCPConnection(boost::asio::io_service &ioService);
    };

    boost::asio::io_service ioService;
    boost::asio::ip::tcp::acceptor acceptor;
    std::list<std::weak_ptr<TCPConnection>> clients;
    std::mutex clientsMutex;

    bool running;
    std::thread refreshDataThread;
    std::thread mainCommunicationThread;

    LatencyDatabase &latencyDatabase;

    std::vector<std::string> dataViewLines;
    std::mutex dataMutex;

    void refreshDataFunc(std::chrono::microseconds refreshTime);
    void updateData();
    std::string getLatency(LatencyDatabase::ProtocolType protocol,
                           const LatencyDatabase::Host &data) const;
    void updateClientView(TCPConnection &connection);
    std::vector<u8> clearDisplayMessage() const;

    void startCommunication();
    void asyncAccept();
    void asyncRead(std::shared_ptr<TCPConnection> connection);
    void sendInitialMessage(std::shared_ptr<TCPConnection> connection);
    void handleAccept(const boost::system::error_code &error,
                      std::shared_ptr<TCPConnection> connection);
    void handleRead(const boost::system::error_code &error, std::size_t bytesCount,
                    std::vector<u8> *rawBuf, std::shared_ptr<TCPConnection> connection);
    void sendResponse(TCPConnection &connection, const std::vector<u8> &data);
    void sendResponse(TCPConnection &connection, const std::vector<std::vector<u8>> &data);
};

#endif