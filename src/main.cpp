#include "pcap_reader.h"

#include <cerrno>
#include <clocale>
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define mkdir _mkdir
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

bool create_directory(const std::string& path)
{
#ifdef _WIN32
    int result = _mkdir(path.c_str());
    return result == 0 || errno == EEXIST;
#else
    int result = mkdir(path.c_str(), 0755);
    return result == 0 || errno == EEXIST;
#endif
}

void PressAnyKey()
{
    std::cout << "\nНажмите любую клавишу..." << std::endl;
    std::cin.get();
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else
    std::setlocale(LC_ALL, "ru_RU.UTF-8");
#endif
    std::cout << "=== PCAP PARSER ===" << std::endl;

    if (argc != 2)
    {
        std::cout << "\nИспользуем: " << argv[0] << " <pcap_file>" << std::endl;
        std::cout << "\nПодсказка: напишите путь до pcap файла" << std::endl;
        PressAnyKey();
        return 1;
    }

    const std::string pcap_file = argv[1];

    std::cout << "\nРаботаем с <pcap_file>: " << pcap_file << std::endl;
    // Создаем объект класса
    PcapReader reader;

    if (!reader.open(pcap_file))
    {
        std::cout << "Error: не получается открыть pcap файл!" << std::endl;
        std::cout << "Убедитесь, что файл существует и он .pcap" << std::endl;
        PressAnyKey();
        return 1;
    }

    reader.read_and_analyze_packets();

    // Вывод результата
    reader.print_basic_info();
    std::cout << "\n=== СТАТИСТИКА ДЛИН ПАКЕТОВ ===" << std::endl;
    reader.print_length_stats_by_length();
    reader.print_length_stats_by_count();

    std::cout << "\n=== СТАТИСТИКА ПАР MAC ===" << std::endl;
    reader.print_mac_pair_stats();

    // reader.print_ipv4_packet_list();
    // reader.print_ipv6_packet_list();

    std::cout << "\n=== СОЗДАНИЕ ВЫХОДНЫХ ФАЙЛОВ ===" << std::endl;

    const std::string result_dir = "result";
    std::cout << "Попытка создания папки: " << result_dir << std::endl;

    if (!create_directory(result_dir))
    {
        std::cerr << "Warning: Не удалось создать папку " << result_dir << " (errno: " << errno << " - " << ")"
                  << std::endl;
        std::cout << "Файлы будут сохранены в текущей директории" << std::endl;
    } else {
        std::cout << "Папка " << result_dir << " создана или уже существует" << std::endl;
    }

#ifdef _WIN32
    std::string ipv4_filename = result_dir + "\\ipv4_packets.pack2";
    std::string ipv6_filename = result_dir + "\\ipv6_packets.pack4";
#else
    std::string ipv4_filename = result_dir + "/ipv4_packets.pack2";
    std::string ipv6_filename = result_dir + "/ipv6_packets.pack4";
#endif

    std::cout << "Попытка сохранения файлов:" << std::endl;
    std::cout << "IPv4: " << ipv4_filename << std::endl;
    std::cout << "IPv6: " << ipv6_filename << std::endl;

    bool ipv4_saved = reader.save_ipv4_packets(ipv4_filename);
    bool ipv6_saved = reader.save_ipv6_packets(ipv6_filename);

#if defined(NDEBUG)
    const char* build_cfg = "Release";
#else
    const char* build_cfg = "Debug";
#endif

    if (ipv4_saved && ipv6_saved)
    {
        std::cout << "\nСборка: " << build_cfg << '\n';
        std::cout << "Все выходные файлы созданы!\n";
    }

    PressAnyKey();
    return 0;
}
