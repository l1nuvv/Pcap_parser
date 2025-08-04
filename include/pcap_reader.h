#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "ethernet_structs.h"
#include "pcap_structs.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

class PcapReader {
private:
    static constexpr size_t ETHERNET_HEADER_SIZE = 14;
    static constexpr size_t MAC_ADDRESS_SIZE     = 6;
    static constexpr size_t IPV4_ETHERTYPE       = 0x0800;
    static constexpr size_t IPV6_ETHERTYPE       = 0x86DD;

    std::vector<uint8_t> buffer;
    size_t               buffer_pos  = 0;
    size_t               buffer_size = 0;
    pcap_header_t        global_header;
    uint32_t             packet_count {0};

    std::map<uint32_t, uint32_t> length_stats;
    std::map<MacPair, uint32_t>  mac_pair_stats;

    std::vector<std::vector<uint8_t>> ipv4_packets;
    std::vector<std::vector<uint8_t>> ipv6_packets;
    uint32_t                          ipv4_count {0};
    uint32_t                          ipv6_count {0};

    std::string mac_to_string(const uint8_t *mac) const;
    std::string format_ipv4_adress(const uint8_t *addr) const;
    std::string format_ipv6_adress(const uint8_t *addr) const;
    void        analyze_ethernet_header(const uint8_t *ethernet_data);
    void        process_single_packet(const pcaprec_header_t &packet_header, const uint8_t* packet_data);
    void        print_length_stats_impl(bool sort_by_count) const;
    void        extract_ip_packet(const uint8_t *ethernet_data, uint32_t total_length, uint16_t ethertype);
    void        print_ip_packet_list(const std::vector<std::vector<uint8_t>> &packets, const std::string &protocol_name,
                                     bool is_ipv4) const;

public:
    PcapReader()  = default;
    ~PcapReader() = default;

    bool     open(const std::string &filename);
    uint32_t read_and_analyze_packets();
    uint32_t get_linktype() const;

    void print_basic_info() const;
    void print_length_stats_by_length() const;
    void print_length_stats_by_count() const;
    void print_mac_pair_stats() const;
    void print_ipv4_packet_list() const;
    void print_ipv6_packet_list() const;

    bool save_ipv4_packets(const std::string &filename) const;
    bool save_ipv6_packets(const std::string &filename) const;

    PcapReader(const PcapReader &)            = delete;
    PcapReader &operator=(const PcapReader &) = delete;
};

#endif // PCAP_READER_H