//
// Created by l1nuvv on 10.08.2025.
//

#ifndef PCAP_CONSTANTS_H
#define PCAP_CONSTANTS_H

#include <cstddef>
#include <cstdint>

namespace pcap_constants
{
    // PCAP файл константы
    static const uint32_t PCAP_MAGIC_NUMBER   = 0xa1b2c3d4;
    static const uint32_t PCAP_R_MAGIC_NUMBER = 0xd4c3b2a1;

    // Ethernet константы
    static const size_t   ETHERNET_HEADER_SIZE = 14;
    static const size_t   MAC_ADDRESS_SIZE     = 6;
    static const uint16_t IPV4_ETHERTYPE       = 0x0800;
    static const uint16_t IPV6_ETHERTYPE       = 0x86DD;

    // IP заголовки минимальные размеры
    static const size_t IPV4_HEADER_MIN_SIZE = 20;
    static const size_t IPV6_HEADER_SIZE     = 40;

    // Общие ограничения
    static const size_t   MAX_PACKET_SIZE = 65535;
    static const uint32_t DEFAULT_SNAPLEN = 65535;

    // Смещения в байтах
    static const size_t ETHERTYPE_BYTE_SHIFT = 8;
    static const size_t IPV4_SRC_ADDR_OFFSET = 12;
    static const size_t IPV4_DST_ADDR_OFFSET = 16;
    static const size_t IPV6_SRC_ADDR_OFFSET = 8;
    static const size_t IPV6_DST_ADDR_OFFSET = 24;

    // Бенчмарки
    static const int TRIALS = 100;

} // namespace pcap_constants

#endif // PCAP_CONSTANTS_H
