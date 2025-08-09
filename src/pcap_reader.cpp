//
// Created by l1nuvv on 30.07.2025.
//

#include "pcap_reader.h"

#include <chrono>

bool PcapReader::open(const std::string &filename)
{
    std::ifstream file(filename.c_str(), std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: не получается открыть файл в бинарном режиме " << filename << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    if (size < sizeof(pcap_header_t)) {
        std::cerr << "Error: файл слишком мал для pcap header" << std::endl;
        return false;
    }
    file.seekg(0, std::ios::beg);

    buffer.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
        std::cerr << "Error: не удалось прочитать весь файл в буфер" << std::endl;
        return false;
    }

    const pcap_header_t *header_ptr = reinterpret_cast<const pcap_header_t *>(buffer.data());
    global_header                   = *header_ptr;
    if (global_header.magic_number != 0xa1b2c3d4) {
        std::cerr << "Error: неправильный magic number(сигнатура)" << std::endl;
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
    size_t offset = sizeof(pcap_header_t);
    while (offset + sizeof(pcaprec_header_t) <= buffer.size()) {
        const pcaprec_header_t *packet_header_ptr = reinterpret_cast<const pcaprec_header_t *>(buffer.data() + offset);
        pcaprec_header_t        packet_header     = *packet_header_ptr;
        offset += sizeof(pcaprec_header_t);

        if (offset + packet_header.incl_len > buffer.size()) {
            std::cerr << "Error: выход за пределы буфера - неправильная длина пакета\n";
            break;
        }

        process_single_packet(packet_header, buffer.data() + offset);
        offset += packet_header.incl_len;
        packet_count++;
    }
    ipv4_count = ip_packet_manager_obj.get_ipv4_count();
    ipv6_count = ip_packet_manager_obj.get_ipv6_count();

    return packet_count;
}

void PcapReader::process_single_packet(const pcaprec_header_t &packet_header, const uint8_t *packet_data)
{
    length_stats[packet_header.incl_len]++;
    if (packet_header.incl_len >= ETHERNET_HEADER_SIZE) {
        ethernet_parser_obj.analyze_ethernet_header(packet_data, packet_header.incl_len);
        const auto *mac_pair_ethernet_header = reinterpret_cast<const ethernet_header_t *>(packet_data);
        uint16_t    ethertype_be             = mac_pair_ethernet_header->ethertype;
        uint16_t    ethertype                = static_cast<uint16_t>((ethertype_be >> ETHERTYPE_BYTE_SHIFT) |
                                                                     (ethertype_be << ETHERTYPE_BYTE_SHIFT));
        ip_packet_manager_obj.extract_ip_packet(packet_data, packet_header.incl_len, ethertype);
    }
}


void PcapReader::print_length_stats_sort(bool sort_by_count) const
{
    if (sort_by_count) {
        std::vector<std::pair<uint32_t, uint32_t>> sorted_stats;

        for (const auto &pair: length_stats) {
            sorted_stats.emplace_back(pair.first, pair.second);
        }
        auto start = std::chrono::high_resolution_clock::now();

        std::sort(sorted_stats.begin(), sorted_stats.end(),
                  [](const std::pair<uint32_t, uint32_t> &a, const std::pair<uint32_t, uint32_t> &b) {
                      return a.second < b.second;
                  });

        auto end      = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        std::cout << "Время сортировки для std::sort : " << duration.count() << " микросекунд" << std::endl;


        for (const auto &pair: sorted_stats) {
            std::cout << "Длина пакета " << pair.first << ": количество " << pair.second << std::endl;
        }
    } else {
        for (const auto &pair: length_stats) {
            std::cout << "Длина пакета " << pair.first << ": количество " << pair.second << std::endl;
        }
    }
}
/*void PcapReader::print_length_stats_multimap(bool sort_by_count) const
{
    if (sort_by_count) {
        for (const auto &pair: length_stats) {
            sorted_stats.emplace_back(pair.first, pair.second);
        }
        auto start = std::chrono::high_resolution_clock::now();
        std::multimap<>
    }
}*/


void PcapReader::print_basic_info() const
{
    std::cout << "Linktype: " << global_header.network << std::endl;
    std::cout << "Всего пакетов: " << packet_count << std::endl;
    std::cout << "IPv4 пакетов: " << ipv4_count << std::endl;
    std::cout << "IPv6 пакетов: " << ipv6_count << std::endl;
}


void PcapReader::print_length_stats_by_length() const
{
    std::cout << "В порядке возрастания длин: " << std::endl;
    print_length_stats_sort(false);
}

void PcapReader::print_length_stats_by_count() const
{
    std::cout << "\nВ порядке возрастания количества: " << std::endl;
    print_length_stats_sort(true);
}

void PcapReader::print_mac_pair_stats() const
{
    ethernet_parser_obj.print_mac_pair_stats();
}

void PcapReader::print_ipv4_packet_list() const
{
    ip_packet_manager_obj.print_ipv4_packet_list();
}

void PcapReader::print_ipv6_packet_list() const
{
    ip_packet_manager_obj.print_ipv6_packet_list();
}

bool PcapReader::save_ipv4_packets(const std::string &filename) const
{
    return ip_packet_manager_obj.save_ipv4_packets(filename);
}

bool PcapReader::save_ipv6_packets(const std::string &filename) const
{
    return ip_packet_manager_obj.save_ipv6_packets(filename);
}