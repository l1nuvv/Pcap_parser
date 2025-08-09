//
// Created by l1nuvv on 05.08.2025.
//

#ifndef PCAP_PARSER_ETHERNETPARSER_H
#define PCAP_PARSER_ETHERNETPARSER_H

#include "structs/ethernet_structs.h"
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

class ethernet_parser {
private:

    std::map<MacPair, uint64_t> mac_pair_stats;
    std::string                 mac_to_string(const uint8_t *mac) const;

public:
    ethernet_parser()  = default;
    ~ethernet_parser() = default;

    void analyze_ethernet_header(const uint8_t *ethernet_data, size_t length);
    void print_mac_pair_stats() const;
};

#endif //PCAP_PARSER_ETHERNETPARSER_H
