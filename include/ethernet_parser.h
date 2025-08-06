//
// Created by l1nuvv on 05.08.2025.
//

#ifndef PCAP_PARSER_ETHERNETPARSER_H
#define PCAP_PARSER_ETHERNETPARSER_H

#include "ethernet_structs.h"
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

class ethernet_parser {
private:
    static const size_t MAC_ADDRESS_SIZE = 6;

    std::map<MacPair, uint32_t> mac_pair_stats;
    std::string                 mac_to_string(const uint8_t *mac) const;

public:
    ethernet_parser()  = default;
    ~ethernet_parser() = default;
    void analyze_ethernet_header(const uint8_t *ethernet_data);
    void print_mac_pair_stats() const;
};

#endif //PCAP_PARSER_ETHERNETPARSER_H
