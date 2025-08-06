#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "ethernet_structs.h"
#include "pcap_structs.h"

#include "ethernet_parser.h"
#include "ip_packet_manager.h"

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
    static const size_t ETHERNET_HEADER_SIZE = 14;

    std::vector<uint8_t> buffer;
    size_t               buffer_pos  = 0;
    size_t               buffer_size = 0;
    pcap_header_t        global_header;
    uint32_t             packet_count;

    uint32_t ipv4_count;
    uint32_t ipv6_count;

    std::map<uint32_t, uint32_t> length_stats;

    ethernet_parser   ethernet_parser;
    ip_packet_manager ip_packet_manager;

    void process_single_packet(const pcaprec_header_t &packet_header, const uint8_t *packet_data);
    void print_length_stats_impl(bool sort_by_count) const;


public:
    PcapReader() : packet_count(0), ipv4_count(0), ipv6_count(0) {};
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