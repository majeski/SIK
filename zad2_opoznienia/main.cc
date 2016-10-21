#include <iostream>
#include <ctime>
#include <cstdlib>

#include <boost/exception/diagnostic_information.hpp>

#include "SDServerClient.h"
#include "LatencyDatabase.h"
#include "UDPService.h"
#include "ICMPEchoPacket.h"
#include "ICMPService.h"
#include "TCPService.h"
#include "TELNETServer.h"

struct Services {
    Services(boost::asio::io_service &io, LatencyDatabase &lb, u16 udpServerPort)
        : udp(io, lb, udpServerPort), icmp(io, lb), tcp(io, lb) {
    }

    UDPService udp;
    ICMPService icmp;
    TCPService tcp;
};

struct RunConfiguration {
    u16 udpPort;
    u16 telnetPort;
    std::chrono::seconds latencyMeasurementInterval;
    std::chrono::seconds multicastLookupInterval;
    std::chrono::milliseconds telnetInterfaceRefreshInterval;
    bool TCPServiceAvailable;
};

void measureLatency(Services &services, LatencyDatabase &lb, std::chrono::seconds loopTime);
RunConfiguration parseArguments(int argc, char **argv);

int main(int argc, char **argv) {
    srand((unsigned)time(nullptr));

    RunConfiguration configuration = parseArguments(argc, argv);

    std::cout << std::boolalpha;
    std::cout << "UDP port: " << configuration.udpPort << std::endl
              << "TELNET port: " << configuration.telnetPort << std::endl
              << "Czas pomiedzy pomiarami opoznien: "
              << configuration.latencyMeasurementInterval.count() << "s" << std::endl
              << "Czas pomiedzy wykrywaniem komputerow: "
              << configuration.multicastLookupInterval.count() << "s" << std::endl
              << "Czas pomiedzy aktualizacjami interfejsu uzytkownika: "
              << configuration.telnetInterfaceRefreshInterval.count() / 1000.0 << "s" << std::endl
              << "Rozglaszanie dostepu do uslugi _ssh._tcp: " << configuration.TCPServiceAvailable
              << std::endl;

    LatencyDatabase lb;
    TELNETServer telnetSrv(configuration.telnetPort, lb);
    SDServerClient dnsSD(lb);

    boost::asio::io_service mainIO;
    boost::asio::io_service::work work(mainIO);
    Services services(mainIO, lb, configuration.udpPort);

    try {
        services.udp.startListening();
        services.icmp.startListening();
        telnetSrv.run(configuration.telnetInterfaceRefreshInterval);
        dnsSD.run(configuration.multicastLookupInterval, configuration.TCPServiceAvailable);
    } catch (...) {
        std::cerr << __func__ << ": " << boost::current_exception_diagnostic_information();
        return EXIT_FAILURE;
    }

    std::thread measureThread(
        measureLatency, std::ref(services), std::ref(lb), configuration.latencyMeasurementInterval);

    try {
        mainIO.run();
    } catch (std::exception &e) {
        std::cerr << __func__ << ": " << e.what() << std::endl;
    } catch (...) {
        std::cerr << __func__ << ": " << boost::current_exception_diagnostic_information()
                  << std::endl;
    }
}

void measureLatency(Services &services, LatencyDatabase &lb, std::chrono::seconds loopTime) {
    while (true) {
        auto hosts = lb.getAll();
        std::vector<boost::asio::ip::address_v4> tcpAddrs;
        std::vector<boost::asio::ip::address_v4> udpAddrs;
        for (auto x : hosts) {
            if (x.second.isProtocolAvailable(LatencyDatabase::ProtocolType::TCP)) {
                tcpAddrs.push_back(x.first);
            }
            if (x.second.isProtocolAvailable(LatencyDatabase::ProtocolType::UDP)) {
                udpAddrs.push_back(x.first);
            }
        }

        services.udp.measureLatency(udpAddrs);
        services.icmp.measureLatency(udpAddrs);
        services.tcp.measureLatency(tcpAddrs);

        std::this_thread::sleep_for(loopTime);
    }
}

bool isUnsignedInteger(const char *str);
bool isUnsignedDouble(const char *str);
u16 parseToPort(const char *str);
std::chrono::seconds parseToSeconds(const char *str);
std::chrono::milliseconds parseSecondsInDouble(const char *str);

// port serwera do pomiaru opóźnień przez UDP: 3382 (-u)
// port serwera do połączeń z interfejsem użytkownika: 3637 (-U)
// czas pomiędzy pomiarami opóźnień: 1 sekunda (-t)
// czas pomiędzy wykrywaniem komputerów: 10 sekund (-T)
// czas pomiędzy aktualizacjami interfejsu użytkownika: 1 sekunda (-v)
// rozgłaszanie dostępu do usługi _ssh._tcp: domyślnie wyłączone (-s)
RunConfiguration parseArguments(int argc, char **argv) {
    RunConfiguration res{3382, 3637, std::chrono::seconds(1), std::chrono::seconds(10),
                         std::chrono::seconds(1), false};

    opterr = 0;
    bool ok = true;
    int arg;

    try {
        while (ok && (arg = getopt(argc, argv, "u:: U:: t:: T:: v:: s")) != -1) {
            switch (arg) {
                case 'u':
                    res.udpPort = parseToPort(optarg);
                    break;
                case 'U':
                    res.telnetPort = parseToPort(optarg);
                    break;
                case 't':
                    res.latencyMeasurementInterval = parseToSeconds(optarg);
                    break;
                case 'T':
                    res.multicastLookupInterval = parseToSeconds(optarg);
                    break;
                case 'v':
                    res.telnetInterfaceRefreshInterval = parseSecondsInDouble(optarg);
                    break;
                case 's':
                    res.TCPServiceAvailable = true;
                    break;
                default:
                    throw UnknownFormatException();
            }
        }
        if (optind != argc) {
            throw UnknownFormatException();
        }
    } catch (UnknownFormatException &) {
        std::cout << "Usage: %s [-u port] [-U port] [-t time] [-T time] [-v time] [-s]"
                  << std::endl;
        exit(EXIT_SUCCESS);
    }
    return res;
}

u16 parseToPort(const char *str) {
    if (str && std::atoi(str) <= 0xFFFF && isUnsignedInteger(str)) {
        return std::atoi(str);
    }
    throw UnknownFormatException();
}

std::chrono::seconds parseToSeconds(const char *str) {
    if (str && isUnsignedInteger(str)) {
        return std::chrono::seconds(std::atoi(str));
    }
    throw UnknownFormatException();
}

std::chrono::milliseconds parseSecondsInDouble(const char *str) {
    if (str && isUnsignedDouble(str)) {
        return std::chrono::milliseconds(std::lround(std::atof(str) * 1000.0));
    }
    throw UnknownFormatException();
}

bool isUnsignedDouble(const char *str) {
    unsigned dots = 0;
    while (*str) {
        if (!isdigit(*str) && *str != '.') {
            return false;
        }
        if (*str == '.') {
            dots++;
        }
        str++;
    }
    return dots <= 1;
}

bool isUnsignedInteger(const char *str) {
    while (*str) {
        if (!isdigit(*str)) {
            return false;
        }
        str++;
    }
    return true;
}