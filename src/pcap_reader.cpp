//
// Created by l1nuvv on 30.07.2025.
//

#include "pcap_reader.h"
#include <algorithm>


bool PcapReader::open(const std::string& filename)
{
    std::ifstream file(filename.c_str(), std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cerr << "Error: не получается открыть файл в бинарном режиме " << filename << std::endl;
        return false;
    }
    std::streamsize size = file.tellg();
    if (size < 0 || static_cast<std::size_t>(size) < sizeof(pcap_header_t))
    {
        std::cerr << "Error: файл слишком мал для pcap header" << std::endl;
        return false;
    }
    file.seekg(0, std::ios::beg);

    buffer_size = static_cast<size_t>(size);
    buffer      = std::make_shared<CArrayWrapper<uint8_t> >(buffer_size);

    if (!file.read(reinterpret_cast<char*>(buffer->raw_data()), size))
    {
        std::cerr << "Error: не удалось прочитать весь файл в буфер" << std::endl;
        buffer.reset();
        buffer_size = 0;
        return false;
    }

    if (buffer_size < sizeof(pcap_header_t))
    {
        std::cerr << "Error: файл повреждён (меньше pcap_header_t)" << std::endl;
        return false;
    }
    const auto* header_ptr = reinterpret_cast<const pcap_header_t*>(buffer->raw_data());
    global_header          = *header_ptr;

    if (global_header.magic_number != pcap_constants::PCAP_MAGIC_NUMBER
        && global_header.magic_number != pcap_constants::PCAP_R_MAGIC_NUMBER)
    {
        std::cerr << "Error: неправильный magic number(сигнатура)" << std::endl;
        return false;
    }

    return true;
}


/*bool PcapReader::open(const std::string &filename)
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
}*/

uint32_t PcapReader::get_linktype() const
{
    return global_header.network;
}

uint32_t PcapReader::read_and_analyze_packets()
{
    if (!buffer || buffer_size < sizeof(pcap_header_t))
    {
        std::cerr << "Error: буфер пуст или слишком мал" << std::endl;
        return 0;
    }

    size_t offset       = sizeof(pcap_header_t);
    const uint8_t* base = buffer->raw_data();

    while (offset + sizeof(pcaprec_header_t) <= buffer_size)
    {
        const auto* packet_header_ptr  = reinterpret_cast<const pcaprec_header_t*>(base + offset);
        pcaprec_header_t packet_header = *packet_header_ptr;

        offset += sizeof(pcaprec_header_t);

        if (offset + packet_header.incl_len > buffer_size)
        {
            std::cerr << "Error: выход за пределы буфера - неправильная длина пакета\n";
            break;
        }

        const uint8_t* packet_data = base + offset;
        process_single_packet(packet_header, packet_data);
        offset += packet_header.incl_len;
        packet_count++;
    }
    ipv4_count = ip_packet_manager_obj.get_ipv4_count();
    ipv6_count = ip_packet_manager_obj.get_ipv6_count();

    return packet_count;
}

void PcapReader::process_single_packet(const pcaprec_header_t& packet_header, const uint8_t* packet_data)
{
    length_stats[packet_header.incl_len]++;
    if (packet_header.incl_len >= pcap_constants::ETHERNET_HEADER_SIZE)
    {
        ethernet_parser_obj.analyze_ethernet_header(packet_data, packet_header.incl_len);
        const auto* mac_pair_ethernet_header = reinterpret_cast<const ethernet_header_t*>(packet_data);
        uint16_t ethertype_be = mac_pair_ethernet_header->ethertype;
        uint16_t ethertype = static_cast<uint16_t>((ethertype_be >> pcap_constants::ETHERTYPE_BYTE_SHIFT)
                                                   | (ethertype_be << pcap_constants::ETHERTYPE_BYTE_SHIFT));
        ip_packet_manager_obj.extract_ip_packet(packet_data, packet_header.incl_len, ethertype);
    }
}


void PcapReader::print_length_stats_sort(bool sort_by_count) const
{
    if (!sort_by_count)
    {
        for (std::map<uint32_t, uint32_t>::const_iterator it = length_stats.begin(); it != length_stats.end(); ++it)
        {
            std::cout << "Длина пакета " << it->first << ": количество " << it->second << std::endl;
        }
        return;
    }

    long long avg_sort_time     = benchmark_std_sort(length_stats); // Бенчмарк std::sort
    long long duration_multimap = benchmark_multimap(length_stats); // Бенчмарк std::multimap

    // Вывод бенчмарка
    std::cout << "=== БЕНЧМАРК ===" << std::endl;
    std::cout << "std::sort: " << avg_sort_time << " мкс" << std::endl;
    std::cout << "std::multimap: " << duration_multimap << " мкс" << std::endl << std::endl;

    // Вывод результата сортировки
    std::vector<std::pair<uint32_t, uint32_t> > sorted_stats;
    sorted_stats.reserve(length_stats.size());
    for (auto length_stat: length_stats)
    {
        sorted_stats.emplace_back(length_stat.first, length_stat.second);
    }

    std::sort(sorted_stats.begin(),
              sorted_stats.end(),
              [](const std::pair<uint32_t, uint32_t>& a, const std::pair<uint32_t, uint32_t>& b) {
                  if (a.second != b.second)
                  {
                      return a.second < b.second;
                  }
                  return a.first < b.first;
              });

    for (auto sorted_stat: sorted_stats)
    {
        std::cout << "Длина пакета " << sorted_stat.first << ": количество " << sorted_stat.second << std::endl;
    }
}

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

bool PcapReader::save_ipv4_packets(const std::string& filename) const
{
    return ip_packet_manager_obj.save_ipv4_packets(filename);
}

bool PcapReader::save_ipv6_packets(const std::string& filename) const
{
    return ip_packet_manager_obj.save_ipv6_packets(filename);
}
