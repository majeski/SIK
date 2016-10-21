#ifndef DNS_FORMAT__H
#define DNS_FORMAT__H

#include <vector>

#include "DNSPacket.h"
#include "bitops.h"

namespace dns_format {
bool isPointer(u8 octet);
u8 getOffset(u8 pointer);

std::vector<u8> stringToDomain(const std::string &str);
std::string domainToString(const std::vector<u8> &domain);

std::vector<u8> firstLabel(const std::vector<u8> &domain);
std::vector<u8> withoutFirstLabel(const std::vector<u8> &domain);

std::vector<u8> getDomainName(raw_data_it begin, raw_data_it &it, raw_data_it end,
                              u16 maxLength = 255);
DNSPacket::Question getQuestion(raw_data_it begin, raw_data_it &it, raw_data_it end);
DNSPacket::ResourceRecord getResourceRecord(raw_data_it begin, raw_data_it &it, raw_data_it end);
}

#endif