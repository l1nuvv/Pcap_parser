//
// Created by l1nuvv on 03.08.2025.
//

#ifndef ETHERNET_STRUCTS_H
#define ETHERNET_STRUCTS_H

#include "pcap_constants.h"
#include <cstdint>
#include <string>


#pragma pack(push,1)
typedef struct EthernetHeader
{
    uint8_t  dst_mac[pcap_constants::MAC_ADDRESS_SIZE];
    uint8_t  src_mac[pcap_constants::MAC_ADDRESS_SIZE];
    uint16_t ethertype;
} ethernet_header_t;
#pragma pack(pop)

static_assert(sizeof(ethernet_header_t) == pcap_constants::ETHERNET_HEADER_SIZE,
              "Ethernet header должен быть ровно 14 байт");

struct MacPair
{
    std::string src_mac;
    std::string dst_mac;

    bool operator<(const MacPair &other) const
    {
        if (src_mac != other.src_mac) { return src_mac < other.src_mac; }
        return dst_mac < other.dst_mac;
    }
};

#endif //ETHERNET_STRUCTS_H