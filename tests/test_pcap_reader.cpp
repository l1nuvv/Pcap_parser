#include "pcap_reader.h"
#include "pcap_structs.h"
#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>
#include <vector>

class PcapReaderTest: public ::testing::Test {
protected:
    void SetUp() override
    {
        // Создаем тестовый PCAP файл
        createValidTestPcapFile();
        createInvalidTestFile();
    }

    void TearDown() override
    {
        // Удаляем тестовые файлы
        std::remove("test_valid.pcap");
        std::remove("test_invalid.pcap");
        std::remove("test_output_ipv4.pack2");
        std::remove("test_output_ipv6.pack4");
    }

    void createValidTestPcapFile()
    {
        std::ofstream file("test_valid.pcap", std::ios::binary);

        // Создаем правильный PCAP заголовок
        pcap_header_t header;
        file.write(reinterpret_cast<const char *>(&header), sizeof(header));

        // Создаем тестовый пакет с IPv4
        pcaprec_header_t packet_header = {};
        packet_header.ts_sec           = 1234567890;
        packet_header.ts_usec          = 123456;
        packet_header.incl_len         = 54; // Ethernet (14) + IPv4 (20) + данные (20)
        packet_header.orig_len         = 54;

        file.write(reinterpret_cast<const char *>(&packet_header), sizeof(packet_header));

        // Создаем пакет данных
        std::vector<uint8_t> packet_data(54, 0);

        // Ethernet заголовок
        // Destination MAC: 00:11:22:33:44:55
        packet_data[0] = 0x00;
        packet_data[1] = 0x11;
        packet_data[2] = 0x22;
        packet_data[3] = 0x33;
        packet_data[4] = 0x44;
        packet_data[5] = 0x55;

        // Source MAC: aa:bb:cc:dd:ee:ff
        packet_data[6]  = 0xaa;
        packet_data[7]  = 0xbb;
        packet_data[8]  = 0xcc;
        packet_data[9]  = 0xdd;
        packet_data[10] = 0xee;
        packet_data[11] = 0xff;

        // EtherType = IPv4 (0x0800)
        packet_data[12] = 0x08;
        packet_data[13] = 0x00;

        // IPv4 заголовок (начинается с 14-го байта)
        packet_data[14] = 0x45; // Version 4, Header length 5*4=20
        packet_data[15] = 0x00; // Type of service
        packet_data[16] = 0x00; // Total length (high)
        packet_data[17] = 0x28; // Total length (low) = 40 bytes

        // Source IP: 192.168.1.1 (смещение 26-29 от начала пакета)
        packet_data[26] = 192;
        packet_data[27] = 168;
        packet_data[28] = 1;
        packet_data[29] = 1;

        // Destination IP: 192.168.1.2 (смещение 30-33 от начала пакета)
        packet_data[30] = 192;
        packet_data[31] = 168;
        packet_data[32] = 1;
        packet_data[33] = 2;

        file.write(reinterpret_cast<const char *>(packet_data.data()), packet_data.size());
        file.close();
    }

    void createInvalidTestFile()
    {
        std::ofstream file("test_invalid.pcap", std::ios::binary);
        // Записываем неправильный magic number
        uint32_t wrong_magic = 0x12345678;
        file.write(reinterpret_cast<const char *>(&wrong_magic), sizeof(wrong_magic));
        file.close();
    }
};

// Тест создания объекта
TEST_F(PcapReaderTest, CreateObject)
{
    PcapReader reader;
    // Если объект создался, тест пройден
    EXPECT_TRUE(true);
}

// Тест открытия несуществующего файла
TEST_F(PcapReaderTest, OpenNonExistentFile)
{
    PcapReader reader;
    bool       result = reader.open("file_that_does_not_exist.pcap");
    EXPECT_FALSE(result); // ИСПРАВЛЕНО: должно быть FALSE!
}

// Тест открытия валидного файла
TEST_F(PcapReaderTest, OpenValidFile)
{
    PcapReader reader;
    bool       result = reader.open("test_valid.pcap");
    EXPECT_TRUE(result);
}

// Тест открытия файла с неправильным magic number
TEST_F(PcapReaderTest, OpenInvalidMagicNumber)
{
    PcapReader reader;
    bool       result = reader.open("test_invalid.pcap");
    EXPECT_FALSE(result);
}

// Тест получения linktype
TEST_F(PcapReaderTest, GetLinktypeAfterOpen)
{
    PcapReader reader;
    EXPECT_TRUE(reader.open("test_valid.pcap"));

    uint32_t linktype = reader.get_linktype();
    EXPECT_EQ(linktype, 1); // Должен быть 1 для Ethernet
}

// Тест чтения пакетов
TEST_F(PcapReaderTest, ReadPackets)
{
    PcapReader reader;
    ASSERT_TRUE(reader.open("test_valid.pcap"));

    uint32_t packet_count = reader.read_and_analyze_packets();
    EXPECT_GT(packet_count, 0); // Должен быть хотя бы 1 пакет
    EXPECT_EQ(packet_count, 1); // В нашем тестовом файле ровно 1 пакет
}

// Тест сохранения IPv4 пакетов
TEST_F(PcapReaderTest, SaveIPv4Packets)
{
    PcapReader reader;
    ASSERT_TRUE(reader.open("test_valid.pcap"));
    reader.read_and_analyze_packets();

    bool result = reader.save_ipv4_packets("test_output_ipv4.pack2");
    EXPECT_TRUE(result);

    // Проверяем, что файл действительно создался
    std::ifstream test_file("test_output_ipv4.pack2");
    EXPECT_TRUE(test_file.good());
    test_file.close();
}

// Тест сохранения IPv6 пакетов (должен быть пустым для нашего тестового файла)
TEST_F(PcapReaderTest, SaveIPv6Packets)
{
    PcapReader reader;
    ASSERT_TRUE(reader.open("test_valid.pcap"));
    reader.read_and_analyze_packets();

    bool result = reader.save_ipv6_packets("test_output_ipv6.pack4");
    EXPECT_TRUE(result); // Функция должна возвращать true даже если пакетов нет
}

// Тест проверки состояния до открытия файла
TEST_F(PcapReaderTest, GetLinktypeBeforeOpen)
{
    PcapReader reader;
    // До открытия файла linktype должен быть значением по умолчанию
    uint32_t linktype = reader.get_linktype();
    EXPECT_EQ(linktype, 1); // Значение по умолчанию из структуры
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    std::cout << "Запуск тестов PCAP Reader..." << std::endl;

    int result = RUN_ALL_TESTS();

    if (result == 0) {
        std::cout << "Все тесты прошли успешно!" << std::endl;
    } else {
        std::cout << "Некоторые тесты не прошли!" << std::endl;
    }

    return result;
}