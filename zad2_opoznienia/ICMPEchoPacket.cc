#include "ICMPEchoPacket.h"

ICMPEchoPacket::ICMPEchoPacket()
    : type(ICMPType::REQUEST), code(0), identifier(0), seqNumber(0), data(0) {
}

ICMPEchoPacket::ICMPEchoPacket(const std::vector<u8> &rawPacket, std::size_t bytesToRead,
                               bool rawPacketWithIPHeader) {
    auto it = rawPacket.begin();
    auto end = rawPacket.end();

    if (rawPacketWithIPHeader) {
        u8 ihl = bitops::getU8(it, end) % (1 << 4);
        ihl = ihl * 4 - 1;
        for (unsigned i = 0; i < ihl; i++) {
            (void)bitops::getU8(it, end);
        }
    }
    {
        // accepts only REPLY
        auto tmpType = bitops::getU8(it, end);
        if (tmpType != ICMPType::REPLY) {
            throw UnknownFormatException();
        }
        type = ICMPType::REPLY;
    }

    code = bitops::getU8(it, end);
    u16 checksum = bitops::getU16(it, end);
    identifier = bitops::getU16(it, end);
    seqNumber = bitops::getU16(it, end);
    data = bitops::getU32(it, end);

    if (calcChecksum() != checksum || it - bytesToRead != rawPacket.begin()) {
        throw UnknownFormatException();
    }
}

std::vector<u8> ICMPEchoPacket::generateNetworkFormat() const {
    std::vector<u8> res;
    res.push_back(type);
    res.push_back(code);
    bitops::addTo(res, calcChecksum());
    bitops::addTo(res, identifier);
    bitops::addTo(res, seqNumber);
    bitops::addTo(res, data);
    return res;
}

u16 ICMPEchoPacket::calcChecksum() const {
    unsigned int sum = (((u16)type) << 8) + code + identifier + seqNumber;

    u16 part2 = data % (1 << 16);
    u16 part1 = data >> 16;
    sum += part1 + part2;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}
