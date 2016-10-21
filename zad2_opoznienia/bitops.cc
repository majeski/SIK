#include <boost/asio.hpp>

#include "bitops.h"

#if defined(__linux__)
#include <endian.h>
#define htonll(x) htobe64(x)
#define ntohll(x) be64toh(x)
#endif

UnknownFormatException::UnknownFormatException(std::string str)
    : std::runtime_error(std::move(str)){};

namespace bitops {

void addTo(std::vector<u8> &v, u16 val) {
    auto u8pair = divide(val);
    v.push_back(u8pair.first);
    v.push_back(u8pair.second);
}

void addTo(std::vector<u8> &v, u32 val) {
    auto u8v = divide(val);
    for (u8 x : u8v) {
        v.push_back(x);
    }
}

void addTo(std::vector<u8> &v, u64 val) {
    auto u8v = divide(val);
    for (u8 x : u8v) {
        v.push_back(x);
    }
}

u64 getU64(raw_data_it &it, raw_data_it end) {
    u32 res[2];
    for (unsigned i = 0; i < 2; i++) {
        res[i] = getU32(it, end);
    }
    return bitops::merge(res[0], res[1]);
}

u32 getU32(raw_data_it &it, raw_data_it end) {
    u16 res[2];
    for (unsigned i = 0; i < 2; i++) {
        res[i] = getU16(it, end);
    }
    return bitops::merge(res[0], res[1]);
}

u16 getU16(raw_data_it &it, raw_data_it end) {
    u8 res[2];
    for (unsigned i = 0; i < 2; i++) {
        res[i] = getU8(it, end);
    }
    return bitops::merge(res[0], res[1]);
}

u8 getU8(raw_data_it &it, raw_data_it end) {
    u8 res;
    if (it == end) {
        throw UnknownFormatException{};
    }
    res = *it;
    ++it;
    return res;
}

std::vector<u8> divide(u32 val) {
    std::vector<u8> res(4);
    res[3] = val & 0xFFFF;
    res[2] = (val >> 8) & 0xFFFF;
    res[1] = (val >> 16) & 0xFFFF;
    res[0] = (val >> 24) & 0xFFFF;
    return res;
}

std::pair<u8, u8> divide(u16 val) {
    return {(val >> 8) & 0xFFFF, val & 0xFFFF};
}

u32 addrToU32(boost::asio::ip::address_v4 addr) {
    return (u32)addr.to_ulong();
}

boost::asio::ip::address_v4 u32ToAddr(u32 addr) {
    return boost::asio::ip::address_v4(addr);
}

u32 merge(u8 a, u8 b, u8 c, u8 d) {
    return merge(merge(a, b), merge(c, d));
}

u16 merge(u8 first, u8 second) {
    u16 res = first;
    res = (res << 8) + second;
    return res;
}

u32 merge(u16 first, u16 second) {
    u32 res = first;
    res = (res << 16) + second;
    return res;
}

u64 merge(u32 first, u32 second) {
    u64 res = first;
    res = (res << 32) + second;
    return res;
}

std::vector<u8> divide(u64 val) {
    std::vector<u8> res(8);
    res[7] = val & 0xFFFF;
    res[6] = (val >> 8) & 0xFFFF;
    res[5] = (val >> 16) & 0xFFFF;
    res[4] = (val >> 24) & 0xFFFF;
    res[3] = (val >> 32) & 0xFFFF;
    res[2] = (val >> 40) & 0xFFFF;
    res[1] = (val >> 48) & 0xFFFF;
    res[0] = (val >> 56) & 0xFFFF;
    return res;
}

u16 hton(u16 val) {
    return htons(val);
}

u16 ntoh(u16 val) {
    return ntohs(val);
}

u32 hton(u32 val) {
    return htonl(val);
}

u32 ntoh(u32 val) {
    return ntohl(val);
}

u64 hton(u64 val) {
    return htonll(val);
}

u64 ntoh(u64 val) {
    return ntohll(val);
}

}  // bitops