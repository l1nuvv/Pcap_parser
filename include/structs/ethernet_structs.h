//
// Created by l1nuvv on 03.08.2025.
//

#ifndef ETHERNET_STRUCTS_H
#define ETHERNET_STRUCTS_H

#include <cstdint>
#include <string>

typedef struct EthernetHeader
{
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} ethernet_header_t;

static_assert(sizeof(ethernet_header_t) == 14, "Ethernet header должен быть ровно 14 байт");

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