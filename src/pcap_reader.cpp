//
// Created by l1nuvv on 30.07.2025.
//

#include "pcap_reader.h"

PcapReader::~PcapReader()
{
    if (file.is_open()) { file.close(); }
}

bool PcapReader::open(const std::string &filename)
{
    file.open(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file in binary mode " << filename << std::endl;
        return false;
    }

    file.read(reinterpret_cast<char *>(&global_header), sizeof(global_header));
    if (file.gcount() != sizeof(global_header)) {
        std::cerr << "Error: File too small for pcap header" << std::endl;
        return false;
    }

    if (global_header.magic_number != 0xa1b2c3d4) {
        std::cerr << "Error: Not a valid pcap file (wrong magic number)" << std::endl;
        return false;
    }
    return true;
}

uint32_t PcapReader::get_linktype() const
{
    return global_header.network;
}

uint32_t PcapReader::read_and_analyze_packets()
{
    file.seekg(sizeof(global_header), std::ios::beg);
    packet_count = 0;
    ipv4_count   = 0;
    ipv6_count   = 0;

    pcaprec_header_t packet_header;
    while (file.read(reinterpret_cast<char *>(&packet_header), sizeof(packet_header))) {
        if (file.gcount() != sizeof(packet_header)) { break; }
        process_single_packet(packet_header);
        packet_count++;
    }
    return packet_count;
}

void PcapReader::process_single_packet(const pcaprec_header_t &packet_header)
{
    length_stats[packet_header.incl_len]++;
    if (packet_header.incl_len >= ETHERNET_HEADER_SIZE) {
        std::vector<uint8_t> full_packet_data(packet_header.incl_len);
        file.read(reinterpret_cast<char *>(full_packet_data.data()), packet_header.incl_len);
        if (file.gcount() == packet_header.incl_len) {
            analyze_ethernet_header(full_packet_data.data());
            extract_ip_packet(full_packet_data.data(), packet_header.incl_len,
                              (full_packet_data[12] << 8) | full_packet_data[13]);
        } else {
            file.seekg(packet_header.incl_len - file.gcount(), std::ios::cur);
        }
    } else {
        file.seekg(packet_header.incl_len, std::ios::cur);
    }
}

std::string PcapReader::mac_to_string(const uint8_t *mac) const
{
    std::stringstream ss;
    for (size_t i = 0; i < MAC_ADDRESS_SIZE; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return ss.str();
}

void PcapReader::analyze_ethernet_header(const uint8_t *ethernet_header)
{
    MacPair mac_pair;
    mac_pair.dst_mac = mac_to_string(&ethernet_header[0]);
    mac_pair.src_mac = mac_to_string(&ethernet_header[6]);
    mac_pair_stats[mac_pair]++;
}

void PcapReader::print_length_stats_impl(bool sort_by_count) const
{
    if (sort_by_count) {
        std::vector<std::pair<uint32_t, uint32_t>> sorted_stats;

        for (const auto &pair: length_stats) {
            sorted_stats.emplace_back(pair.first, pair.second);
        }
        std::sort(sorted_stats.begin(), sorted_stats.end(),
                  [](const std::pair<uint32_t, uint32_t> &a, const std::pair<uint32_t, uint32_t> &b) {
                      return a.second < b.second;
                  });

        for (const auto &pair: sorted_stats) {
            std::cout << "Длина пакета " << pair.first << ": количество " << pair.second << std::endl;
        }
    } else {
        for (const auto &pair: length_stats) {
            std::cout << "Длина пакета " << pair.first << ": количество " << pair.second << std::endl;
        }
    }
}

void PcapReader::extract_ip_packet(const uint8_t *ethernet_data, uint32_t total_length, uint16_t ethertype)
{
    if (total_length <= ETHERNET_HEADER_SIZE) return;

    const uint8_t *ip_data   = ethernet_data + ETHERNET_HEADER_SIZE;
    uint32_t       ip_length = total_length - ETHERNET_HEADER_SIZE;

    if (ethertype == IPV4_ETHERTYPE && ip_length >= 20) {
        uint8_t version = (ip_data[0] >> 4) & 0x0F;
        if (version == 4) {
            ipv4_count++;
            std::vector<uint8_t> ipv4_packet(ip_data, ip_data + ip_length);
            ipv4_packets.push_back(std::move(ipv4_packet));
        }
    } else if (ethertype == IPV6_ETHERTYPE && ip_length >= 40) {
        uint8_t version = (ip_data[0] >> 4) & 0x0F;
        if (version == 6) {
            ipv6_count++;
            std::vector<uint8_t> ipv6_packet(ip_data, ip_data + ip_length);
            ipv6_packets.push_back(std::move(ipv6_packet));
        }
    }
}

std::string PcapReader::format_ipv4_adress(const uint8_t *addr) const
{
    return std::to_string(addr[0]) + "." + std::to_string(addr[1]) + "." + std::to_string(addr[2]) + "." +
           std::to_string(addr[3]);
}

std::string PcapReader::format_ipv6_adress(const uint8_t *addr) const
{
    std::stringstream ss;
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(addr[i]) << std::setfill('0')
           << std::setw(2) << static_cast<int>(addr[i + 1]);
    }
    return ss.str();
}


void PcapReader::print_basic_info() const
{
    std::cout << "Linktype: " << global_header.network << std::endl;
    std::cout << "Всего пакетов: " << packet_count << std::endl;
    std::cout << "IPv4 пакетов: " << ipv4_count << std::endl;
    std::cout << "IPv6 пакетов: " << ipv6_count << std::endl;
}


void PcapReader::print_ip_packet_list(const std::vector<std::vector<uint8_t>> &packets,
                                      const std::string &protocol_name, bool is_ipv4) const
{
    std::cout << "\n=== " << protocol_name << " СПИСОК ПАКЕТОВ ===" << std::endl;
    std::cout << "Всего " << protocol_name << " пакетов: " << packets.size() << std::endl;

    if (packets.empty()) {
        std::cout << "Пакетов " << protocol_name << " не найдено" << std::endl;
        return;
    }

    for (size_t i = 0; i < packets.size(); ++i) {
        const auto &packet          = packets[i];
        size_t      min_header_size = is_ipv4 ? 20 : 40;
        if (packet.size() >= min_header_size) {
            std::cout << "Пакет " << (i + 1) << ": ";

            if (is_ipv4) {
                std::cout << format_ipv4_adress(&packet[12]) << " -> " << format_ipv4_adress(&packet[16]) << std::endl;
            } else {
                std::cout << format_ipv6_adress(&packet[8]) << " -> " << format_ipv6_adress(&packet[24]) << std::endl;
            }
        }
    }
}

void PcapReader::print_length_stats_by_length() const
{
    std::cout << "В порядке возрастания длин: " << std::endl;
    print_length_stats_impl(false);
}

void PcapReader::print_length_stats_by_count() const
{
    std::cout << "\nВ порядке возрастания количества: " << std::endl;
    print_length_stats_impl(true);
}

void PcapReader::print_mac_pair_stats() const
{
    for (const auto &pair: mac_pair_stats) {
        std::cout << pair.first.src_mac << " -> " << pair.first.dst_mac << ": " << pair.second << std::endl;
    }
}

void PcapReader::print_ipv4_packet_list() const
{
    print_ip_packet_list(ipv4_packets, "IPv4", true);
}

void PcapReader::print_ipv6_packet_list() const
{
    print_ip_packet_list(ipv6_packets, "IPv6", false);
}

bool PcapReader::save_ipv4_packets(const std::string &filename) const
{
    if (ipv4_packets.empty()) {
        std::cout << "IPv4 пакетов для записи не найдено" << std::endl;
        return true;
    }
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "Error: нельзя создать файл " << filename << std::endl;
        return false;
    }

    for (const auto &packet: ipv4_packets) {
        uint16_t packet_size = static_cast<uint16_t>(packet.size());
        if (packet.size() > 65535) {
            std::cerr << "Warning: IPv4 пакет слишком большой (" << packet.size() << " байтов), сжатие до 65535"
                      << std::endl;
            packet_size = 65535;
        }

        ofs.write(reinterpret_cast<const char *>(&packet_size), sizeof(packet_size));

        size_t bytes_to_write = std::min(static_cast<size_t>(packet_size), packet.size());
        ofs.write(reinterpret_cast<const char *>(packet.data()), bytes_to_write);
    }
    ofs.close();
    return true;
}

bool PcapReader::save_ipv6_packets(const std::string &filename) const
{
    if (ipv6_packets.empty()) {
        std::cout << "IPv6 пакетов для записи не найдено" << std::endl;
        return true;
    }
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "Error: нельзя создать файл " << filename << std::endl;
        return false;
    }
    for (const auto &packet: ipv6_packets) {
        uint32_t packet_size = static_cast<uint32_t>(packet.size());
        ofs.write(reinterpret_cast<const char *>(&packet_size), sizeof(packet_size));
        ofs.write(reinterpret_cast<const char *>(packet.data()), packet.size());
    }
    ofs.close();
    return true;
}
