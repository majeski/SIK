#ifndef SD_SERVER_CLIENT__H
#define SD_SERVER_CLIENT__H

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <thread>
#include <mutex>
#include <map>
#include <memory>

#include "DNSPacket.h"
#include "LatencyDatabase.h"
#include "bitops.h"

class SDServerClient {
public:
    SDServerClient(LatencyDatabase &LatencyDatabase);
    ~SDServerClient() = default;
    SDServerClient(const SDServerClient &) = delete;
    SDServerClient(SDServerClient &&) = delete;
    SDServerClient &operator=(const SDServerClient &) = delete;
    SDServerClient &operator=(SDServerClient &&) = delete;

    void run(std::chrono::seconds lookupInterval, bool tcpAvailable);
    void stopServices();

private:
    using endpoint_t = boost::asio::ip::udp::endpoint;
    using time_point_t = std::chrono::time_point<std::chrono::system_clock>;

    static const u32 DEFAULT_TTL = 4500;
    static const std::string TCP_SERVICE;
    static const std::string OPOZNIENIA_SERVICE;
    static const endpoint_t MDNS_MULTICAST_EP;

    static const unsigned PTR_TIME_IDX = 0;
    static const unsigned A_TIME_IDX = 1;
    std::unique_ptr<time_point_t> lastMutlicastResponses[2];
    bool tcpAvailable;
    std::string hostname;
    bool hostnameEstablished;

    boost::asio::io_service ioService;

    boost::asio::ip::udp::socket socket;
    std::mutex socketMutex;
    std::thread lookupThread;
    std::thread receiveThread;

    // host name i.e. first label of domain name
    std::map<std::vector<u8>, time_point_t> knownHostNames;
    std::mutex knownHostNamesMutex;
    std::vector<u8> buffer;
    DNSPacket queryPTRPacket;

    LatencyDatabase &latencyDatabase;

    void prepareSocket();
    void prepareHostname();
    void prepareQueryPacket(bool unicastResponseRequested);

    void multicastLookupThreadFunc(std::chrono::seconds lookupInterval);
    void receiveThreadFunc();

    void receiveMessage(endpoint_t senderEndpoint, endpoint_t msgDestination,
                        std::size_t bytesToRead);
    bool ignorePacket(const DNSPacket &packet, endpoint_t senderEndpoint) const;
    bool ignoreQuestion(const DNSPacket::Question &q) const;

    void handleQuestions(const DNSPacket &packet, endpoint_t senderEndpoint,
                         bool directedQuery = false);
    void responseToLegacyUnicastQuery(u16 queryID, const DNSPacket::Question &q,
                                      endpoint_t senderEndpoint);
    void handleUnicastQuery(const DNSPacket::Question &q, endpoint_t senderEndpoint);
    void responseViaMulticast(const DNSPacket::Question &q, endpoint_t senderEndpoint);

    DNSPacket::ResourceRecord generatePTRAnswer(const DNSPacket::Question &q) const;
    DNSPacket::ResourceRecord generateAAnswer(const DNSPacket::Question &q,
                                              endpoint_t senderEndpoint) const;
    DNSPacket::ResourceRecord generatePlainAnswer() const;

    void handleResponses(const DNSPacket &packet, endpoint_t senderEndpoint);
    void handlePTRResponse(const DNSPacket::ResourceRecord &response);
    void handleAResponse(const DNSPacket::ResourceRecord &response);
    void sendAQuery(const std::vector<u8> &domain);

    void send(const std::vector<u8> &bytes, endpoint_t dst,
              std::chrono::microseconds delay = std::chrono::microseconds(0));
    std::chrono::microseconds delayForPTRResponse() const;

    boost::asio::ip::address_v4 getHostAddr(boost::asio::ip::address_v4 peer) const;

    // arg - at least first label of domain
    bool isHostKnown(const std::vector<u8> &domain);
    void addKnownHost(const std::vector<u8> &domain, u16 ttl);

    // arg - full domain name
    bool supportedService(const std::vector<u8> &domain);
};

#endif