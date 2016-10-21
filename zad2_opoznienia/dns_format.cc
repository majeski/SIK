#include "dns_format.h"
#include "bitops.h"

namespace dns_format {

std::vector<u8> stringToDomain(const std::string &str) {
    static const char dot = '.';

    std::vector<u8> res;
    auto name = dot + str;
    for (auto it = name.begin(); it != name.end(); ++it) {
        if (*it == dot) {
            auto countIt = it;
            do {
                ++countIt;
            } while (countIt != name.end() && *countIt != dot);

            res.push_back(countIt - it - 1);
        } else {
            res.push_back(*it);
        }
    }
    if (res.back() != 0) {
        res.push_back(0);
    }

    return res;
}

std::string domainToString(const std::vector<u8> &domain) {
    std::string res;
    int count = 0;
    for (auto c : domain) {
        if (!count) {
            count = c;
            if (!res.empty()) {
                res += '.';
            }
        } else {
            res += c;
            count--;
        }
    }
    return res;
}

std::vector<u8> firstLabel(const std::vector<u8> &domain) {
    u8 count = domain[0];
    std::vector<u8> res(count + 2);
    for (u8 i = 0; i <= count; i++) {
        res[i] = domain[i];
    }
    res[count + 1] = 0;
    return res;
}

std::vector<u8> withoutFirstLabel(const std::vector<u8> &domain) {
    u8 prefix = domain[0];
    std::vector<u8> res(domain.size() - prefix - 1);
    for (unsigned i = prefix + 1; i < domain.size(); i++) {
        res[i - prefix - 1] = domain[i];
    }
    return res;
}

DNSPacket::Question getQuestion(raw_data_it begin, raw_data_it &it, raw_data_it end) {
    DNSPacket::Question question;
    question.qname = getDomainName(begin, it, end);
    question.qtype = bitops::getU16(it, end);
    question.qclass = bitops::getU16(it, end);
    question.unicastResponseRequested = question.qclass & (1 << 15);
    question.qclass &= 0x7F;
    return question;
}

DNSPacket::ResourceRecord getResourceRecord(raw_data_it begin, raw_data_it &it, raw_data_it end) {
    DNSPacket::ResourceRecord rr;
    rr.name = getDomainName(begin, it, end);
    u16 rrtype = bitops::getU16(it, end);
    rr.rrclass = bitops::getU16(it, end);
    rr.ttl = bitops::getU32(it, end);
    u16 rdlength = bitops::getU16(it, end);

    if (rrtype == DNSPacket::DNSType::PTR) {
        rr.setPTRAnswer(getDomainName(begin, it, end));

        if (dns_format::withoutFirstLabel(rr.getPtrAnswer()) != rr.name) {
            // name != [name].service.local.
            throw UnknownFormatException();
        }
    } else if (rrtype == DNSPacket::DNSType::A) {
        if (rdlength != 4) {
            throw UnknownFormatException{};
        }
        rr.setAAnswer(bitops::getU32(it, end));
    } else {
        for (unsigned i = 0; i < rdlength; i++) {
            // don't need that
            (void)bitops::getU8(it, end);
        }
    }

    // don't want top bit
    rr.rrclass &= 0x7F;

    return rr;
}

bool isPointer(u8 octet) {
    return (octet & 0xC0) == 0xC0;
}

u8 getOffset(u8 pointer) {
    return pointer & (0xFF - 0xC0);
}

std::vector<u8> getDomainName(raw_data_it begin, raw_data_it &it, raw_data_it end, u16 maxLength) {
    std::vector<u8> res;
    unsigned count = 1;

    while (true) {
        if (maxLength == 0) {
            throw UnknownFormatException();
        }
        res.push_back(bitops::getU8(it, end));
        maxLength--;

        if (--count == 0) {
            if (res.back() == 0) {
                break;
            }

            if (isPointer(res.back())) {
                u16 offset = getOffset(res.back());
                if (maxLength == 0) {
                    throw UnknownFormatException();
                }
                offset = (offset << 8) + bitops::getU8(it, end);
                maxLength--;
                res.pop_back();

                auto newIt = begin + offset;
                if (offset >= end - begin) {
                    throw UnknownFormatException("error in compression");
                }
                auto fromPtr = getDomainName(begin, newIt, end, maxLength);
                for (auto octet : fromPtr) {
                    res.push_back(octet);
                }
                break;
            }

            count = res.back() + 1;
        }
    }

    for (auto c : res) {
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
    }
    return res;
}

}  // dns_format