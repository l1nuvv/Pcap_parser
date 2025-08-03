//
// Created by l1nuvv on 29.07.2025.
//
#ifndef PCAP_STRUCTS_H
#define PCAP_STRUCTS_H

#pragma once

#include <cstdint>

#pragma pack(push, 1)

// Глобальный заголовок pcap-файла
typedef struct PCAPGlobalHeader
{
    const uint32_t magic_number  = 0xa1b2c3d4; // сигнатура (magic number)
    const uint16_t version_major = 2;          // основная (major) версия по умолчанию 2
    const uint16_t version_minor = 4;          // дополнительная (minor) версия по умолчанию 4
    const int32_t  thiszone      = 0;          // смещение по времени от GMT (по умолчанию 0)
    const uint32_t sigfigs       = 0;          // точность метки времени (обычно 0)
    const uint32_t snaplen       = 65535;      // максимальная длина пакета (по умолчанию 65535)
    uint32_t       network       = 1;          // тип канального уровня (1 — Ethernet, соответствует linktype)
} pcap_header_t;

// Заголовок записи (пакета) в pcap-файле
typedef struct PCAPRecordHeader
{
    uint32_t ts_sec;   // секунды метки времени (timestamp)
    uint32_t ts_usec;  // микросекунды метки времени
    uint32_t incl_len; // количество байт данных пакета, сохранённых в файле
    uint32_t orig_len; // фактическая длина оригинального пакета в сети
} pcaprec_header_t;

#pragma pack(pop)

#endif //PCAP_STRUCTS_H
