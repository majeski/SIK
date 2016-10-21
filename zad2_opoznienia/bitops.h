#ifndef bitops__H
#define bitops__H

#include <cstdint>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using raw_data_it = std::vector<u8>::const_iterator;

struct UnknownFormatException : public std::runtime_error {
    UnknownFormatException(std::string str = "");
};

namespace bitops {
// merge usage: merge(0xA, 0xB) -> 0xAB
u16 merge(u8 hi, u8 lo);
std::pair<u8, u8> divide(u16 val);

u32 merge(u16 hi, u16 lo);
u32 merge(u8 hihi, u8 hilo, u8 lohi, u8 lolo);
std::vector<u8> divide(u32 val);

u64 merge(u32 hi, u32 lo);
std::vector<u8> divide(u64 val);

void addTo(std::vector<u8> &v, u16 val);
void addTo(std::vector<u8> &v, u32 val);
void addTo(std::vector<u8> &v, u64 val);

u8 getU8(raw_data_it &it, raw_data_it end);
u16 getU16(raw_data_it &it, raw_data_it end);
u32 getU32(raw_data_it &it, raw_data_it end);
u64 getU64(raw_data_it &it, raw_data_it end);

u16 hton(u16 val);
u16 ntoh(u16 val);
u32 hton(u32 val);
u32 ntoh(u32 val);
u64 hton(u64 val);
u64 ntoh(u64 val);

u32 addrToU32(boost::asio::ip::address_v4 addr);
boost::asio::ip::address_v4 u32ToAddr(u32 addr);
}

#endif