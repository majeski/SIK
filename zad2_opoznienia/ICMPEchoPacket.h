#ifndef ICMP_ECHO_PACKET__H
#define ICMP_ECHO_PACKET__H

#include "bitops.h"

class ICMPEchoPacket {
public:
    enum ICMPType : u8 { REPLY = 0, REQUEST = 8 };

    ICMPEchoPacket();
    ICMPEchoPacket(const std::vector<u8> &rawPacket, std::size_t bytesToRead,
                   bool rawPacketWithIPHeader = false);

    ICMPType type;
    u8 code;
    u16 identifier;
    u16 seqNumber;
    u32 data;

    std::vector<u8> generateNetworkFormat() const;

private:
    u16 calcChecksum() const;
};

#endif