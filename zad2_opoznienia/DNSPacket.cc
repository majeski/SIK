#include <exception>

#include "DNSPacket.h"
#include "dns_format.h"

DNSPacket::DNSPacket() : header(HEADER_SIZE) {
}

DNSPacket::DNSPacket(const std::vector<u8> &rawPacket, std::size_t bytesToRead) : DNSPacket() {
    auto it = rawPacket.begin();
    for (unsigned i = 0; i < HEADER_SIZE; i++) {
        header[i] = bitops::getU8(it, rawPacket.end());
    }

    unsigned questionsCount = getQDCount();
    for (unsigned i = 0; i < questionsCount; i++) {
        addQuestion(dns_format::getQuestion(rawPacket.begin(), it, rawPacket.end()));
    }

    unsigned answersCount = getANCount();
    for (unsigned i = 0; i < answersCount; i++) {
        addAnswer(dns_format::getResourceRecord(rawPacket.begin(), it, rawPacket.end()));
    }

    unsigned unsupportedCount = getARCount() + getNSCount();
    for (unsigned i = 0; i < unsupportedCount; i++) {
        // don't want this
        (void)dns_format::getResourceRecord(rawPacket.begin(), it, rawPacket.end());
    }

    if (it - rawPacket.begin() != (long)bytesToRead) {
        throw UnknownFormatException();
    }
}

u16 DNSPacket::getID() const {
    return bitops::merge(header[0], header[1]);
}

bool DNSPacket::getQR() const {
    return header[QR_OCTET] & (1 << QR_POS);
}

u8 DNSPacket::getOpcode() const {
    u8 opcode = header[2];
    // 0xxxx000 -> xxxx0000
    opcode <<= 1;
    // & 11110000
    opcode &= 0xF0;
    return opcode;
}

bool DNSPacket::getAA() const {
    return header[AA_OCTET] & (1 << AA_POS);
}

bool DNSPacket::getTC() const {
    return header[TC_OCTET] & (1 << TC_POS);
}

bool DNSPacket::getRD() const {
    return header[RD_OCTET] & (1 << RD_POS);
}

bool DNSPacket::getRA() const {
    return header[RA_OCTET] & (1 << RA_POS);
}

u8 DNSPacket::getZ() const {
    u8 z = header[3];
    // 0xxxx000 -> xxxx0000
    z <<= 1;
    // & 11100000
    z &= 0x70;
    return z;
}

u8 DNSPacket::getRCode() const {
    u8 rcode = header[3];
    // 0000xxxx -> xxxx0000
    rcode <<= 4;
    // & 11110000
    rcode &= 0xF0;
    return rcode;
}

u16 DNSPacket::getQDCount() const {
    return bitops::merge(header[4], header[5]);
}

u16 DNSPacket::getANCount() const {
    return bitops::merge(header[6], header[7]);
}

u16 DNSPacket::getNSCount() const {
    return bitops::merge(header[8], header[9]);
}

u16 DNSPacket::getARCount() const {
    return bitops::merge(header[10], header[11]);
}

void DNSPacket::setID(u16 val) {
    auto idU8 = bitops::divide(val);
    header[0] = idU8.first;
    header[1] = idU8.second;
}

void DNSPacket::setQR(bool val) {
    if (getQR() != val) {
        if (val) {
            header[QR_OCTET] |= 1 << QR_POS;
        } else {
            header[QR_OCTET] -= 1 << QR_POS;
        }
    }
}

void DNSPacket::setOpcode(u8 val) {
    if (val > 0xF0) {
        throw std::logic_error("opcode must be less than 2^4");
    }

    // & 10000111
    header[2] &= BIT8_MAX - (0xF0 >> 1);
    header[2] |= val >> 1;
}

void DNSPacket::setAA(bool val) {
    if (getAA() != val) {
        if (val) {
            header[AA_OCTET] |= 1 << AA_POS;
        } else {
            header[AA_OCTET] -= 1 << AA_POS;
        }
    }
}

void DNSPacket::setTC(bool val) {
    if (getTC() != val) {
        if (val) {
            header[TC_OCTET] |= 1 << TC_POS;
        } else {
            header[TC_OCTET] -= 1 << TC_POS;
        }
    }
}

void DNSPacket::setRD(bool val) {
    if (getRD() != val) {
        if (val) {
            header[RD_OCTET] |= 1 << RD_POS;
        } else {
            header[RD_OCTET] -= 1 << RD_POS;
        }
    }
}

void DNSPacket::setRA(bool val) {
    if (getRA() != val) {
        if (val) {
            header[RA_OCTET] |= 1 << RA_POS;
        } else {
            header[RA_OCTET] -= 1 << RA_POS;
        }
    }
}

void DNSPacket::setZ(u8 val) {
    if (val >= 0x70) {
        throw std::logic_error("z must be less than 2^3");
    }
    // & 10001111
    header[3] &= 0x8F;
    header[3] |= val >> 1;
}

void DNSPacket::setRCode(u8 val) {
    if (val > 0xF0) {
        throw std::logic_error("rcode must be less than 2^4");
    }
    // & 11110000
    header[3] &= 0xF0;
    header[3] |= val >> 4;
}

std::vector<u8> DNSPacket::generateNetworkFormat() const {
    auto res = header;
    for (const auto &q : questions) {
        for (const auto octet : q.generateNetworkFormat()) {
            res.push_back(octet);
        }
    }
    for (const auto &a : answers) {
        for (const auto octet : a.generateNetworkFormat()) {
            res.push_back(octet);
        }
    }
    return res;
}

void DNSPacket::addQuestion(DNSPacket::Question q) {
    setQDCount(getQDCount() + 1);
    questions.push_back(std::move(q));
}

void DNSPacket::addAnswer(DNSPacket::ResourceRecord a) {
    setANCount(getANCount() + 1);
    answers.push_back(std::move(a));
}

const std::vector<DNSPacket::Question> &DNSPacket::getQuestions() const {
    return questions;
}

const std::vector<DNSPacket::ResourceRecord> &DNSPacket::getAnswers() const {
    return answers;
}

void DNSPacket::setQDCount(u16 val) {
    auto idU8 = bitops::divide(val);
    header[4] = idU8.first;
    header[5] = idU8.second;
}

void DNSPacket::setANCount(u16 val) {
    auto idU8 = bitops::divide(val);
    header[6] = idU8.first;
    header[7] = idU8.second;
}

void DNSPacket::setNSCount(u16 val) {
    auto idU8 = bitops::divide(val);
    header[8] = idU8.first;
    header[9] = idU8.second;
}

void DNSPacket::setARCount(u16 val) {
    auto idU8 = bitops::divide(val);
    header[10] = idU8.first;
    header[11] = idU8.second;
}

DNSPacket::Question::Question() : qtype(0), qclass(0), unicastResponseRequested(false) {
}

std::vector<u8> DNSPacket::Question::generateNetworkFormat() const {
    std::vector<u8> res = qname;
    bitops::addTo(res, qtype);

    if (unicastResponseRequested) {
        u16 qclassWithUnicast = this->qclass | (1 << 15);
        bitops::addTo(res, qclassWithUnicast);
    } else {
        bitops::addTo(res, qclass);
    }
    return res;
}

DNSPacket::ResourceRecord::ResourceRecord()
    : rrclass(DNSPacket::DNSClass::IN),
      ttl(0),
      rrtype(DNSPacket::DNSType::UNSUPPORTED),
      rdlength(0) {
}

u16 DNSPacket::ResourceRecord::getRRType() const {
    return rrtype;
}

void DNSPacket::ResourceRecord::setPTRAnswer(std::vector<u8> domain) {
    rrtype = DNSType::PTR;
    rdata = std::move(domain);
    rdlength = rdata.size();
}

void DNSPacket::ResourceRecord::setAAnswer(u32 address) {
    rrtype = DNSType::A;
    rdlength = 4;
    rdata.clear();
    bitops::addTo(rdata, address);
}

std::vector<u8> DNSPacket::ResourceRecord::generateNetworkFormat() const {
    std::vector<u8> res = name;
    bitops::addTo(res, rrtype);
    bitops::addTo(res, rrclass);
    bitops::addTo(res, ttl);
    bitops::addTo(res, rdlength);
    for (auto octet : rdata) {
        res.push_back(octet);
    }
    return res;
}

u32 DNSPacket::ResourceRecord::getAddress() const {
    if (rrtype != DNSType::A) {
        throw std::logic_error("rrtype != A");
    }
    auto begin = rdata.begin();
    return bitops::getU32(begin, rdata.end());
}

std::vector<u8> DNSPacket::ResourceRecord::getPtrAnswer() const {
    if (rrtype != DNSType::PTR) {
        throw std::logic_error("rrtype != PTR");
    }
    return rdata;
}
