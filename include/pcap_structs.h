//
// Created by l1nuvv on 29.07.2025.
//

#ifndef PCAP_STRUCTS_H
#define PCAP_STRUCTS_H

#pragma once

#include <cstdint>

#pragma pack(push, 1)

//
typedef struct PCAPGlobalHeader
{
    const uint32_t magic_number  = 0xa1b2c3d4; // magic number
    const uint16_t version_major = 2;          // 2 major version number by default
    const uint16_t version_minor = 4;          // 4 minor version number by default
    const int32_t  thiszone      = 0;          // 0 GMT by default
    const uint32_t sigfigs       = 0;          // 0 by default
    const uint32_t snaplen       = 65535;      // 65535 by default
    uint32_t       network       = 1;          // 1 for Ethernet, same as linktype
} pcap_header_t;

typedef struct PCAPRecordHeader
{
    uint32_t ts_sec;   // timestamp seconds
    uint32_t ts_usec;  // timestamp microseconds
    uint32_t incl_len; // number of bytes of packet save in file
    uint32_t orig_len; // actual length of packet
} pcaprec_header_t;
#pragma pack(pop)


#endif //PCAP_STRUCTS_H
