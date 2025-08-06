//
// Created by l1nuvv on 05.08.2025.
//

#ifndef PCAP_PARSER_IPPACKETMANAGER_H
#define PCAP_PARSER_IPPACKETMANAGER_H

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

class ip_packet_manager {
private:
    static const size_t ETHERNET_HEADER_SIZE = 14;
    static const size_t IPV4_ETHERTYPE       = 0x0800;
    static const size_t IPV6_ETHERTYPE       = 0x86DD;
    static const size_t MAX_PACKET_SIZE      = 65535;

    std::vector<std::vector<uint8_t>> ipv4_packets;
    std::vector<std::vector<uint8_t>> ipv6_packets;
    uint32_t                          ipv4_count;
    uint32_t                          ipv6_count;

    std::string format_ipv4_adress(const uint8_t *addr) const;
    std::string format_ipv6_adress(const uint8_t *addr) const;

public:
    ip_packet_manager() : ipv4_count(0), ipv6_count(0) {}
    ~ip_packet_manager() = default;
    void print_ip_packet_list(const std::vector<std::vector<uint8_t>> &packets, const std::string &protocol_name,
                              bool is_ipv4) const;
    void extract_ip_packet(const uint8_t *ethernet_data, uint32_t total_length, uint16_t ethertype);

    uint32_t get_ipv4_count();
    uint32_t get_ipv6_count();

    void print_ipv4_packet_list() const;
    void print_ipv6_packet_list() const;

    bool save_ipv4_packets(const std::string &filename) const;
    bool save_ipv6_packets(const std::string &filename) const;
};


#endif //PCAP_PARSER_IPPACKETMANAGER_H
