# PCAP Parser

![C++](https://img.shields.io/badge/C%2B%2B-11-blue?style=flat&logo=cplusplus&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.5+-064F8C?style=flat&logo=cmake&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey?style=flat)

Консольный парсер PCAP-файлов для анализа сетевого трафика.

## Возможности

- Анализ Ethernet-фреймов (linktype 1)
- Статистика пакетов по длинам и MAC-адресам
- Извлечение IPv4/IPv6 пакетов
- Экспорт в бинарные форматы `.pack2` и `.pack4`

---

## Сборка и запуск

```bash
## Сборка
mkdir build && cd build
cmake ..

## Для Debug
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .

## Для Release
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .


## Использование
./Pcap_parser traffic.pcap
```

Программа создаст папку `result/` со следующими файлами:

- `ipv4_packets.pack2` — IPv4 пакеты  
  Формат: `[2 байта — размер][данные]`

- `ipv6_packets.pack4` — IPv6 пакеты  
  Формат: `[4 байта — размер][данные]`

---

## Пример вывода

```text
=== PCAP PARSER ===
Файл: traffic.pcap
Linktype: 1

Всего пакетов: 22943
IPv4 пакетов: 22883
IPv6 пакетов: 1

=== СТАТИСТИКА ДЛИН ПАКЕТОВ ===
Наиболее частые размеры:
1354 байта: 12144 пакетов
154 байта: 1006 пакетов
1514 байта: 792 пакета

Минимальный размер: 42 байта
Максимальный размер: 1514 байт
Уникальных длин: 160+

=== БЕНЧМАРК СОРТИРОВКИ ===
std::sort:      6 мкс
std::multimap: 11 мкс

=== ТОП MAC-ПАР ===
18:0f:76:1e:6a:1c -> 04:d9:f5:83:c7:c2: 13514
04:d9:f5:83:c7:c2 -> 18:0f:76:1e:6a:1c: 8548
18:0f:76:1e:6a:1c -> ff:ff:ff:ff:ff:ff: 13

=== ВЫХОДНЫЕ ФАЙЛЫ ===
result/ipv4_packets.pack2
result/ipv6_packets.pack4
```

---

## Стек

- C++11
- GCC 11+/MSVC 120+
- CMake 3.5
- Google Test
