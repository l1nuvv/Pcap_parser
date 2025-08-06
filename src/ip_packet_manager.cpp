//
// Created by l1nuvv on 05.08.2025.
//

#include "ip_packet_manager.h"

void ip_packet_manager::extract_ip_packet(const uint8_t *ethernet_data, uint32_t total_length, uint16_t ethertype)
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
uint32_t ip_packet_manager::get_ipv4_count()
{
    return ipv4_count;
}
uint32_t ip_packet_manager::get_ipv6_count()
{
    return ipv6_count;
}

std::string ip_packet_manager::format_ipv4_adress(const uint8_t *addr) const
{
    return std::to_string(addr[0]) + "." + std::to_string(addr[1]) + "." + std::to_string(addr[2]) + "." +
           std::to_string(addr[3]);
}

std::string ip_packet_manager::format_ipv6_adress(const uint8_t *addr) const
{
    std::stringstream ss;
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(addr[i]) << std::setfill('0')
           << std::setw(2) << static_cast<int>(addr[i + 1]);
    }
    return ss.str();
}

void ip_packet_manager::print_ip_packet_list(const std::vector<std::vector<uint8_t>> &packets,
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

void ip_packet_manager::print_ipv4_packet_list() const
{
    print_ip_packet_list(ipv4_packets, "IPv4", true);
}

void ip_packet_manager::print_ipv6_packet_list() const
{
    print_ip_packet_list(ipv6_packets, "IPv6", false);
}

bool ip_packet_manager::save_ipv4_packets(const std::string &filename) const
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
        if (packet.size() > MAX_PACKET_SIZE) {
            std::cerr << "Warning: IPv4 пакет слишком большой (" << packet.size()
                      << " байтов), сжатие до MAX_PACKET_SIZE" << std::endl;
            continue;
        }

        uint16_t packet_size = static_cast<uint16_t>(packet.size());
        ofs.write(reinterpret_cast<const char *>(&packet_size), sizeof(packet_size));
        ofs.write(reinterpret_cast<const char *>(packet.data()), packet_size);
    }
    ofs.close();
    return true;
}

bool ip_packet_manager::save_ipv6_packets(const std::string &filename) const
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
