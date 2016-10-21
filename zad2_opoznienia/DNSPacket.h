#ifndef DNS_PACKET__H
#define DNS_PACKET__H

#include <vector>
#include <cstdint>
#include <string>

#include "bitops.h"

class DNSPacket {
public:
    struct Question;
    struct ResourceRecord;
    enum DNSType : u16 { UNSUPPORTED = 0, A = 1, PTR = 12, ALL = 255 };
    enum DNSClass : u16 { IN = 1 };
    enum DNSQR : bool { RESPONSE = true, QUESTION = false };

    DNSPacket();
    DNSPacket(const std::vector<u8> &rawPacket, std::size_t bytesToRead);

    u16 getID() const;
    bool getQR() const;
    u8 getOpcode() const;
    bool getAA() const;
    bool getTC() const;
    bool getRD() const;
    bool getRA() const;
    u8 getZ() const;
    u8 getRCode() const;
    u16 getQDCount() const;
    u16 getANCount() const;
    u16 getNSCount() const;
    u16 getARCount() const;

    void setID(u16 val);
    void setQR(bool val);
    void setOpcode(u8 val);
    void setAA(bool val);
    void setTC(bool val);
    void setRD(bool val);
    void setRA(bool val);
    void setZ(u8 val);
    void setRCode(u8 val);

    void addQuestion(Question q);
    const std::vector<Question> &getQuestions() const;

    void addAnswer(ResourceRecord a);
    const std::vector<ResourceRecord> &getAnswers() const;

    std::vector<u8> generateNetworkFormat() const;

    struct Question {
        Question();

        std::vector<u8> qname;
        u16 qtype;
        u16 qclass;
        bool unicastResponseRequested;

        std::vector<u8> generateNetworkFormat() const;
    };

    struct ResourceRecord {
        ResourceRecord();

        std::vector<u8> name;
        u16 rrclass;
        u32 ttl;

        u16 getRRType() const;
        void setPTRAnswer(std::vector<u8> domain);
        void setAAnswer(u32 address);
        std::vector<u8> generateNetworkFormat() const;

        // returns ipv4 only if rrtype equals A
        u32 getAddress() const;

        // returns ptr answer only if rrtype equals PTR
        std::vector<u8> getPtrAnswer() const;

    private:
        u16 rrtype;
        u16 rdlength;
        std::vector<u8> rdata;
    };

private:
    static constexpr unsigned HEADER_SIZE = 12;
    static constexpr u8 BIT8_MAX = 0xFF;

    static constexpr unsigned QR_OCTET = 2;
    static constexpr unsigned QR_POS = 7;

    static constexpr unsigned AA_OCTET = 2;
    static constexpr unsigned AA_POS = 2;

    static constexpr unsigned TC_OCTET = 2;
    static constexpr unsigned TC_POS = 1;

    static constexpr unsigned RD_OCTET = 2;
    static constexpr unsigned RD_POS = 0;

    static constexpr unsigned RA_OCTET = 3;
    static constexpr unsigned RA_POS = 7;

    std::vector<u8> header;
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;

    void setQDCount(u16 val);
    void setANCount(u16 val);
    void setNSCount(u16 val);
    void setARCount(u16 val);
};

#endif