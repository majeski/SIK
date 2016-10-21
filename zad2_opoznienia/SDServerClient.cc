#include <iostream>
#include <exception>
#include <thread>
#include <chrono>
#include <cstdint>
#include <boost/bind.hpp>
#include <ifaddrs.h>

#include "DNSPacket.h"
#include "SDServerClient.h"
#include "bitops.h"
#include "dns_format.h"
#include "settings.h"

const std::string SDServerClient::TCP_SERVICE = "_ssh._tcp.local.";
const std::string SDServerClient::OPOZNIENIA_SERVICE = "_opoznienia._udp.local.";
const SDServerClient::endpoint_t SDServerClient::MDNS_MULTICAST_EP(
    boost::asio::ip::address::from_string("224.0.0.251"), 5353);

SDServerClient::SDServerClient(LatencyDatabase &latencyDatabase)
    : hostname(boost::asio::ip::host_name()),
      hostnameEstablished(false),
      ioService(),
      socket(ioService),
      buffer(BUFFER_SIZE),
      latencyDatabase(latencyDatabase) {
    hostname = "Spa";
}

void SDServerClient::run(std::chrono::seconds lookupInterval, bool tcpAvailable) {
    static bool running = false;
    if (!running) {
        prepareSocket();
        this->tcpAvailable = tcpAvailable;

        receiveThread = std::thread(&SDServerClient::receiveThreadFunc, this);
        lookupThread =
            std::thread(&SDServerClient::multicastLookupThreadFunc, this, lookupInterval);
        running = true;
    } else {
        throw std::logic_error("already running");
    }
}

void SDServerClient::prepareSocket() {
    using namespace boost::asio;
    socket.open(ip::udp::v4());
    socket.set_option(socket_base::reuse_address(true));
    socket.bind(ip::udp::endpoint(ip::udp::v4(), MDNS_MULTICAST_EP.port()));
    socket.set_option(ip::multicast::join_group(MDNS_MULTICAST_EP.address()));
    socket.set_option(ip::multicast::enable_loopback(false));

    int opt = 1;
    int x = setsockopt(socket.native_handle(), IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));
    if (x != 0) {
        std::cerr << __func__ << ": " << strerror(errno) << "\n";
        throw std::runtime_error("unable to configure multicast socket");
    }
}

void SDServerClient::multicastLookupThreadFunc(std::chrono::seconds lookupInterval) {
    prepareQueryPacket(true);
    bool unicastQueryDisabled = false;

    while (true) {
        send(queryPTRPacket.generateNetworkFormat(), MDNS_MULTICAST_EP);
        std::this_thread::sleep_for(lookupInterval);

        if (!unicastQueryDisabled) {
            unicastQueryDisabled = true;
            prepareQueryPacket(false);
        }
        if (!hostnameEstablished) {
            prepareHostname();
        }
    }
}

void SDServerClient::prepareQueryPacket(bool unicastResponseRequested) {
    queryPTRPacket = DNSPacket();
    DNSPacket::Question q;

    q.qtype = DNSPacket::DNSType::PTR;
    q.qclass = DNSPacket::DNSClass::IN;
    q.unicastResponseRequested = unicastResponseRequested;

    q.qname = dns_format::stringToDomain(TCP_SERVICE);
    queryPTRPacket.addQuestion(q);

    q.qname = dns_format::stringToDomain(OPOZNIENIA_SERVICE);
    queryPTRPacket.addQuestion(q);
}

void SDServerClient::prepareHostname() {
    unsigned i = 0;
    auto newHostname = hostname;
    do {
        newHostname = hostname + "-" + std::to_string(i++);
    } while (isHostKnown(dns_format::stringToDomain(newHostname)));
    hostname = newHostname;
    hostnameEstablished = true;
    std::cout << "Hostname: " << hostname << std::endl;
}

void SDServerClient::receiveThreadFunc() {
    iovec iov;
    iov.iov_base = buffer.data();
    iov.iov_len = buffer.size();

    msghdr msgInfo;
    memset(&msgInfo, 0, sizeof(msgInfo));
    sockaddr_in peeraddr;
    in_pktinfo pktinfo;
    char cmbuf[0x100];

    msgInfo.msg_name = &peeraddr;
    msgInfo.msg_namelen = sizeof(peeraddr);
    msgInfo.msg_iov = &iov;
    msgInfo.msg_iovlen = 1;
    msgInfo.msg_control = cmbuf;
    msgInfo.msg_controllen = sizeof(cmbuf);

    int native_socket = socket.native_handle();
    while (true) {
        ssize_t recLen = recvmsg(native_socket, &msgInfo, 0);

        bool found = false;
        for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msgInfo); cmsg && !found;
             cmsg = CMSG_NXTHDR(&msgInfo, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                pktinfo = *((in_pktinfo *)CMSG_DATA(cmsg));
                found = true;
            }
        }

        if (recLen == -1 || !found) {
            std::cerr << __func__ << ": " << strerror(errno) << "\n";
        } else {
            endpoint_t senderEndpoint;
            senderEndpoint.address(
                boost::asio::ip::address_v4(bitops::ntoh(peeraddr.sin_addr.s_addr)));
            senderEndpoint.port(bitops::ntoh(peeraddr.sin_port));

            endpoint_t msgDestination;
            msgDestination.address(
                boost::asio::ip::address_v4(bitops::ntoh(pktinfo.ipi_addr.s_addr)));
            msgDestination.port(MDNS_MULTICAST_EP.port());

            receiveMessage(senderEndpoint, msgDestination, recLen);
        }
    }
}

void SDServerClient::receiveMessage(endpoint_t senderEndpoint, endpoint_t msgDestination,
                                    std::size_t bytesToRead) {
    DNSPacket receivedPacket;
    try {
        receivedPacket = DNSPacket(buffer, bytesToRead);
    } catch (UnknownFormatException &) {
        return;
    }

    if (ignorePacket(receivedPacket, senderEndpoint)) {
        return;
    }

    if (receivedPacket.getQR() == DNSPacket::DNSQR::QUESTION && hostnameEstablished) {
        handleQuestions(receivedPacket, senderEndpoint, msgDestination != MDNS_MULTICAST_EP);
    } else {
        handleResponses(receivedPacket, senderEndpoint);
    }
}

bool SDServerClient::ignorePacket(const DNSPacket &packet, endpoint_t senderEndpoint) const {
    if (packet.getOpcode() != 0) {
        return true;
    }
    if (packet.getRCode() != 0) {
        return true;
    }

    return false;
}

void SDServerClient::handleQuestions(const DNSPacket &packet, endpoint_t senderEndpoint,
                                     bool directedQuery) {
    for (const auto &q : packet.getQuestions()) {
        if (ignoreQuestion(q)) {
            continue;
        }

        if (senderEndpoint.port() != MDNS_MULTICAST_EP.port()) {
            // TC legacy unicast queries are not supported
            if (!packet.getTC()) {
                responseToLegacyUnicastQuery(packet.getID(), q, senderEndpoint);
            }
        } else if (directedQuery || q.unicastResponseRequested) {
            handleUnicastQuery(q, senderEndpoint);
        } else {
            responseViaMulticast(q, senderEndpoint);
        }
    }
}

bool SDServerClient::ignoreQuestion(const DNSPacket::Question &q) const {
    if (q.qtype != DNSPacket::DNSType::PTR && q.qtype != DNSPacket::DNSType::A) {
        // unsupported type
        return true;
    }
    if (!tcpAvailable && (q.qname == dns_format::stringToDomain(TCP_SERVICE) ||
                          q.qname == dns_format::stringToDomain(hostname + "." + TCP_SERVICE))) {
        // service not available
        return true;
    }
    if (q.qclass != DNSPacket::DNSClass::IN) {
        // unsupported class
        return true;
    }
    return false;
}

void SDServerClient::responseToLegacyUnicastQuery(u16 queryID, const DNSPacket::Question &q,
                                                  endpoint_t senderEndpoint) {
    static const u32 max_ttl = 10;

    DNSPacket::ResourceRecord answer;
    if (q.qtype == DNSPacket::DNSType::PTR) {
        answer = generatePTRAnswer(q);
    } else if (q.qtype == DNSPacket::DNSPacket::A) {
        answer = generateAAnswer(q, senderEndpoint);
    }
    answer.ttl = max_ttl;

    if (answer.getRRType() == DNSPacket::DNSType::UNSUPPORTED) {
        return;
    }

    DNSPacket response;
    response.setID(queryID);
    response.setQR(DNSPacket::DNSQR::RESPONSE);
    response.addQuestion(q);
    response.addAnswer(answer);

    send(response.generateNetworkFormat(), senderEndpoint);
}

void SDServerClient::handleUnicastQuery(const DNSPacket::Question &q, endpoint_t senderEndpoint) {
    // if the responder has not multicast that record recently (within one quarter of its TTL)
    // multicast the response
    unsigned time_idx;
    if (q.qtype == DNSPacket::DNSType::PTR) {
        time_idx = PTR_TIME_IDX;
    } else {
        time_idx = A_TIME_IDX;
    }

    if (!lastMutlicastResponses[time_idx] ||
        *lastMutlicastResponses[time_idx] <
            std::chrono::system_clock::now() - std::chrono::seconds(DEFAULT_TTL / 4)) {
        responseViaMulticast(q, senderEndpoint);
        return;
    }

    // unicast response
    DNSPacket::ResourceRecord answer;
    std::chrono::microseconds delay(0);
    if (q.qtype == DNSPacket::DNSType::PTR) {
        answer = generatePTRAnswer(q);
        delay = delayForPTRResponse();
    } else if (q.qtype == DNSPacket::DNSPacket::A) {
        answer = generateAAnswer(q, senderEndpoint);
    }

    if (answer.getRRType() == DNSPacket::DNSType::UNSUPPORTED) {
        return;
    }

    DNSPacket response;
    response.setQR(DNSPacket::DNSQR::RESPONSE);
    response.addAnswer(answer);

    send(response.generateNetworkFormat(), senderEndpoint, delay);
}

void SDServerClient::responseViaMulticast(const DNSPacket::Question &q, endpoint_t senderEndpoint) {
    DNSPacket::ResourceRecord answer;
    std::chrono::microseconds delay(0);
    unsigned time_idx = 0;
    if (q.qtype == DNSPacket::DNSType::PTR) {
        answer = generatePTRAnswer(q);
        delay = delayForPTRResponse();
        time_idx = PTR_TIME_IDX;
    } else if (q.qtype == DNSPacket::DNSPacket::A) {
        answer = generateAAnswer(q, senderEndpoint);
        time_idx = A_TIME_IDX;
    }

    if (answer.getRRType() == DNSPacket::DNSType::UNSUPPORTED) {
        return;
    }

    DNSPacket response;
    response.setQR(DNSPacket::DNSQR::RESPONSE);
    response.addAnswer(answer);

    send(response.generateNetworkFormat(), MDNS_MULTICAST_EP, delay);
    lastMutlicastResponses[time_idx].reset(
        new time_point_t(std::chrono::system_clock::now() + delay));
}

DNSPacket::ResourceRecord SDServerClient::generateAAnswer(const DNSPacket::Question &q,
                                                          endpoint_t senderEndpoint) const {
    auto res = generatePlainAnswer();
    res.name = q.qname;

    for (const auto &srvc : {TCP_SERVICE, OPOZNIENIA_SERVICE}) {
        if (q.qname == dns_format::stringToDomain(hostname + "." + srvc)) {
            res.setAAnswer(bitops::addrToU32(getHostAddr(senderEndpoint.address().to_v4())));
        }
    }

    return res;
}

DNSPacket::ResourceRecord SDServerClient::generatePTRAnswer(const DNSPacket::Question &q) const {
    auto res = generatePlainAnswer();
    res.name = q.qname;

    for (const auto &srvc : {TCP_SERVICE, OPOZNIENIA_SERVICE}) {
        if (q.qname == dns_format::stringToDomain(srvc)) {
            res.setPTRAnswer(dns_format::stringToDomain(hostname + "." + srvc));
        }
    }

    return res;
}

DNSPacket::ResourceRecord SDServerClient::generatePlainAnswer() const {
    DNSPacket::ResourceRecord answer;
    answer.ttl = DEFAULT_TTL;
    answer.rrclass = DNSPacket::DNSClass::IN;
    return answer;
}

std::chrono::microseconds SDServerClient::delayForPTRResponse() const {
    // [20; 120]
    return std::chrono::microseconds(rand() % 101 + 20);
}

void SDServerClient::handleResponses(const DNSPacket &packet, endpoint_t senderEndpoint) {
    if (senderEndpoint.port() != MDNS_MULTICAST_EP.port()) {
        return;
    }

    for (const auto &r : packet.getAnswers()) {
        if (r.getRRType() == DNSPacket::DNSType::PTR) {
            handlePTRResponse(r);
        } else if (r.getRRType() == DNSPacket::DNSType::A) {
            handleAResponse(r);
        }
    }
}

void SDServerClient::handlePTRResponse(const DNSPacket::ResourceRecord &response) {
    auto serviceLabels =
        dns_format::domainToString(dns_format::withoutFirstLabel(response.getPtrAnswer()));

    if (!supportedService(response.getPtrAnswer())) {
        return;
    }

    addKnownHost(response.getPtrAnswer(), response.ttl);
    sendAQuery(response.getPtrAnswer());
}

void SDServerClient::sendAQuery(const std::vector<u8> &domain) {
    DNSPacket::Question query;
    query.qname = domain;
    query.qclass = DNSPacket::DNSClass::IN;
    query.qtype = DNSPacket::DNSType::A;

    DNSPacket packet;
    packet.setQR(DNSPacket::DNSQR::QUESTION);
    packet.addQuestion(query);
    send(packet.generateNetworkFormat(), MDNS_MULTICAST_EP);
}

void SDServerClient::handleAResponse(const DNSPacket::ResourceRecord &response) {
    if (!supportedService(response.name) || !isHostKnown(response.name)) {
        return;
    }

    auto serviceLabels = dns_format::domainToString(dns_format::withoutFirstLabel(response.name));

    auto addr = bitops::u32ToAddr(response.getAddress());
    auto ttl = std::chrono::seconds(response.ttl);

    if (serviceLabels == TCP_SERVICE) {
        latencyDatabase.setConnectionAvailable(LatencyDatabase::ProtocolType::TCP, addr, ttl);
    }
    if (serviceLabels == OPOZNIENIA_SERVICE) {
        latencyDatabase.setConnectionAvailable(LatencyDatabase::ProtocolType::UDP, addr, ttl);
    }
}

void SDServerClient::send(const std::vector<u8> &bytes, endpoint_t dst,
                          std::chrono::microseconds delay) {
    if (delay == std::chrono::microseconds(0)) {
        boost::system::error_code ec;
        socketMutex.lock();
        socket.send_to(
            boost::asio::buffer(bytes), dst, boost::asio::ip::udp::socket::message_flags(), ec);
        socketMutex.unlock();
    } else {
        std::thread delayThread([=]() {
            std::this_thread::sleep_for(delay);
            boost::system::error_code ec;
            socketMutex.lock();
            socket.send_to(
                boost::asio::buffer(bytes), dst, boost::asio::ip::udp::socket::message_flags(), ec);
            socketMutex.unlock();
        });
        delayThread.detach();
    }
}

boost::asio::ip::address_v4 SDServerClient::getHostAddr(boost::asio::ip::address_v4 peer) const {
    ifaddrs *addrs;
    getifaddrs(&addrs);

    uint32_t result = 0;
    uint32_t peerAddr = bitops::addrToU32(peer);
    for (ifaddrs *curIf = addrs; curIf; curIf = curIf->ifa_next) {
        if (curIf->ifa_addr && curIf->ifa_addr->sa_family == AF_INET) {
            std::uint32_t addr = bitops::ntoh(((sockaddr_in *)curIf->ifa_addr)->sin_addr.s_addr);
            std::uint32_t netmask =
                bitops::ntoh(((sockaddr_in *)curIf->ifa_netmask)->sin_addr.s_addr);
            if ((netmask & addr) == (netmask & peerAddr)) {
                result = addr;
                break;
            }
        }
    }

    freeifaddrs(addrs);
    return bitops::u32ToAddr(result);
}

void SDServerClient::addKnownHost(const std::vector<u8> &domain, u16 ttl) {
    std::unique_lock<std::mutex>(knownHostNamesMutex);
    auto hostName = dns_format::firstLabel(domain);
    knownHostNames[hostName] = std::chrono::system_clock::now() + std::chrono::seconds(ttl);
}

bool SDServerClient::isHostKnown(const std::vector<u8> &domain) {
    std::unique_lock<std::mutex>(knownHostNamesMutex);

    auto hostname = dns_format::firstLabel(domain);
    if (knownHostNames.find(hostname) == knownHostNames.end()) {
        return false;
    }
    if (knownHostNames[hostname] < std::chrono::system_clock::now()) {
        knownHostNames.erase(hostname);
    }

    return knownHostNames.find(hostname) != knownHostNames.end();
}

bool SDServerClient::supportedService(const std::vector<u8> &domain) {
    auto servicesLabels = dns_format::domainToString(dns_format::withoutFirstLabel(domain));
    return servicesLabels == TCP_SERVICE || servicesLabels == OPOZNIENIA_SERVICE;
}