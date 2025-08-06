//
// Created by l1nuvv on 05.08.2025.
//

#include "ethernet_parser.h"

std::string ethernet_parser::mac_to_string(const uint8_t *mac) const
{
    std::stringstream ss;
    for (size_t i = 0; i < MAC_ADDRESS_SIZE; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return ss.str();
}

void ethernet_parser::analyze_ethernet_header(const uint8_t *ethernet_header)
{
    MacPair mac_pair;
    mac_pair.dst_mac = mac_to_string(&ethernet_header[0]);
    mac_pair.src_mac = mac_to_string(&ethernet_header[6]);
    mac_pair_stats[mac_pair]++;
}

void ethernet_parser::print_mac_pair_stats() const
{
    for (const auto &pair: mac_pair_stats) {
        std::cout << pair.first.src_mac << " -> " << pair.first.dst_mac << ": " << pair.second << std::endl;
    }
}
