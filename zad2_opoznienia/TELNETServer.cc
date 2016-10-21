#include <boost/bind.hpp>
#include <iostream>

#include "TELNETServer.h"
#include "settings.h"

TELNETServer::TELNETServer(u16 port, LatencyDatabase &latencyDatabase)
    : ioService(),
      acceptor(ioService, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      running(false),
      latencyDatabase(latencyDatabase) {
}

void TELNETServer::run(std::chrono::microseconds refreshTime) {
    if (!running) {
        mainCommunicationThread = std::thread(&TELNETServer::startCommunication, this);
        refreshDataThread = std::thread(&TELNETServer::refreshDataFunc, this, refreshTime);
        running = true;
    } else {
        throw std::logic_error("already running");
    }
}

void TELNETServer::refreshDataFunc(std::chrono::microseconds refreshTime) {
    while (true) {
        updateData();
        clientsMutex.lock();
        auto it = clients.begin();
        while (it != clients.end()) {
            auto connection = it->lock();
            if (!connection) {
                it = clients.erase(it);
            } else {
                updateClientView(*connection);
                ++it;
            }
        }
        clientsMutex.unlock();
        std::this_thread::sleep_for(refreshTime);
    }
}

void TELNETServer::updateData() {
    static const auto protocols = LatencyDatabase::allProtocols;
    auto data = latencyDatabase.getAll();

    //    // test
    //    while (data.size() && data.size() != 15) {
    //        data.push_back(data[0]);
    //    }
    //    while (data.size() && data.size() != 30) {
    //        data.push_back(data[1]);
    //    }
    //    // test

    std::sort(data.begin(), data.end(), &TELNETServer::compareHostEntry);

    std::vector<std::string> ips;
    std::vector<std::string> times;
    std::size_t minSpace = CONSOLE_WIDTH;
    double maxAverageLatency = 0;
    for (auto line : data) {
        ips.push_back(line.first.to_string());

        std::string lineTimes;
        for (unsigned i = 0; i < protocols.size(); i++) {
            lineTimes += getLatency(protocols[i], line.second);
            if (i < protocols.size() - 1) {
                lineTimes += " ";
            }
        }
        times.push_back(lineTimes);

        if (CONSOLE_WIDTH < times.back().size() + ips.back().size() + 1) {
            minSpace = 1;
        }
        minSpace = std::min(minSpace, CONSOLE_WIDTH - times.back().size() - ips.back().size() - 1);
        minSpace = std::max(minSpace, (std::size_t)1);
        maxAverageLatency = std::max(maxAverageLatency, line.second.getAverageLatency());
    }

    dataMutex.lock();
    dataViewLines.clear();
    for (unsigned i = 0; i < data.size(); i++) {
        std::string line = ips[i];

        std::size_t spacesCount =
            std::round(data[i].second.getAverageLatency() / maxAverageLatency * minSpace);
        for (std::size_t space = 0;
             space < std::max((std::size_t)1, std::min(spacesCount, minSpace));
             space++) {
            line += ' ';
        }
        line += times[i];
        dataViewLines.push_back(line);
    }
    dataMutex.unlock();
}

bool TELNETServer::compareHostEntry(
    const std::pair<LatencyDatabase::addr_t, LatencyDatabase::Host> &a,
    const std::pair<LatencyDatabase::addr_t, LatencyDatabase::Host> &b) {
    return a.second.getAverageLatency() > b.second.getAverageLatency();
}

std::string TELNETServer::getLatency(LatencyDatabase::ProtocolType protocol,
                                     const LatencyDatabase::Host &data) const {
    if (!data.isProtocolAvailable(protocol)) {
        return "-";
    }

    if (!data.isLatencyKnown(protocol)) {
        return "?";
    }

    return std::to_string(data.getLatency(protocol).count());
}

void TELNETServer::updateClientView(TELNETServer::TCPConnection &connection) {
    std::vector<std::vector<u8>> message;
    message.push_back(clearDisplayMessage());

    dataMutex.lock();
    auto maxRow = std::min((unsigned)dataViewLines.size(),
                           (unsigned)(connection.firstRowPos + CONSOLE_HEIGHT));
    auto minRow = (maxRow <= CONSOLE_HEIGHT) ? 0 : maxRow - CONSOLE_HEIGHT;

    for (unsigned i = minRow; i < maxRow; i++) {
        std::vector<u8> raw;
        for (auto c : dataViewLines[i]) {
            raw.push_back(c);
        }

        // newline
        if (i + 1 != maxRow) {
            raw.push_back(u8(ESC));
            raw.push_back('E');
        }

        message.push_back(raw);
    }
    dataMutex.unlock();
    sendResponse(connection, message);
}

std::vector<u8> TELNETServer::clearDisplayMessage() const {
    return {ESC, '[', '2', 'J', ESC, '[', 'H'};
}

void TELNETServer::startCommunication() {
    asyncAccept();

    try {
        ioService.run();
    } catch (...) {
        std::cerr << "TELNET Server aborted" << std::endl;
    }
}

void TELNETServer::asyncAccept() {
    auto newConnection = std::make_shared<TCPConnection>(ioService);
    acceptor.async_accept(
        newConnection->socket,
        boost::bind(
            &TELNETServer::handleAccept, this, boost::asio::placeholders::error, newConnection));
}

void TELNETServer::handleAccept(const boost::system::error_code &error,
                                std::shared_ptr<TCPConnection> connection) {
    static const std::vector<u8> initialMsg{IAC, WILL, SUPPRESS_GO_AHEAD, IAC, WILL, TELNET_ECHO};
    asyncAccept();
    if (error) {
        return;
    }

    boost::system::error_code ec;

    connection->socketMutex.lock();
    connection->socket.write_some(boost::asio::buffer(initialMsg), ec);
    connection->socketMutex.unlock();

    if (!ec) {
        clientsMutex.lock();
        clients.push_back(connection);
        clientsMutex.unlock();

        asyncRead(connection);
    }
}

void TELNETServer::asyncRead(std::shared_ptr<TCPConnection> connection) {
    auto *buf = new std::vector<u8>(SMALL_BUFFER_SIZE);

    connection->socketMutex.lock();
    connection->socket.async_read_some(boost::asio::buffer(*buf, buf->size()),
                                       boost::bind(&TELNETServer::handleRead,
                                                   this,
                                                   boost::asio::placeholders::error,
                                                   boost::asio::placeholders::bytes_transferred,
                                                   buf,
                                                   connection));
    connection->socketMutex.unlock();
}

void TELNETServer::handleRead(const boost::system::error_code &error, std::size_t bytesCount,
                              std::vector<u8> *bufRaw, std::shared_ptr<TCPConnection> connection) {
    std::unique_ptr<std::vector<u8>> buf(bufRaw);
    if (error) {
        return;
    }

    for (unsigned i = 0; i < bytesCount; i++) {
        connection->receivedData.push_back(buf->operator[](i));
    }

    auto &data = connection->receivedData;
    while (!data.empty()) {
        if (data[0] == IAC) {
            if (data.size() < 3) {
                // need to wait for the rest of message
                break;
            }

            if (data[1] == WILL) {
                sendResponse(*connection, {IAC, DONT, data[2]});
            } else if (data[1] == DO) {
                // receive response to two initial commands
                if (connection->receivedCommandsCount < 2 &&
                    (data[2] == TELNET_ECHO || data[2] == SUPPRESS_GO_AHEAD)) {
                    // ignore
                } else {
                    sendResponse(*connection, {IAC, WONT, data[2]});
                }
                connection->receivedCommandsCount++;
            }

            data.erase(data.begin(), data.begin() + 3);
            continue;
        }

        if (data[0] == 'Q' || data[0] == 'q') {
            data.erase(data.begin());
            if (connection->firstRowPos > 0) {
                connection->firstRowPos--;
                updateClientView(*connection);
            }
            continue;
        }

        if (data[0] == 'A' || data[0] == 'a') {
            data.erase(data.begin());
            dataMutex.lock();
            if (connection->firstRowPos + CONSOLE_HEIGHT < dataViewLines.size()) {
                connection->firstRowPos++;
                dataMutex.unlock();
                updateClientView(*connection);
            } else {
                dataMutex.unlock();
            }
            continue;
        }

        // unknown character
        sendResponse(*connection, std::vector<u8>{BELL});
        data.erase(data.begin());
    }

    asyncRead(connection);
}

void TELNETServer::sendResponse(TCPConnection &connection, const std::vector<u8> &data) {
    boost::system::error_code ec;
    connection.socketMutex.lock();
    connection.socket.write_some(boost::asio::buffer(data), ec);
    connection.socketMutex.unlock();
}

void TELNETServer::sendResponse(TCPConnection &connection,
                                const std::vector<std::vector<u8>> &data) {
    boost::system::error_code ec;
    std::unique_lock<std::mutex>(connection.socketMutex);

    for (auto &line : data) {
        connection.socket.write_some(boost::asio::buffer(line), ec);
        if (ec) {
            break;
        }
    }
}

TELNETServer::TCPConnection::TCPConnection(boost::asio::io_service &ioService)
    : socket(ioService), firstRowPos(0), receivedCommandsCount(0) {
}
