//
// Created by l1nuvv on 14.08.2025.
//

#ifndef PCAP_PARSER_BENCHMARKS_H
#define PCAP_PARSER_BENCHMARKS_H

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <map>
#include <random>
#include <utility>
#include <vector>

long long benchmark_std_sort(const std::map<uint32_t, uint32_t> &length_stats);
long long benchmark_multimap(const std::map<uint32_t, uint32_t> &length_stats);


#endif //PCAP_PARSER_BENCHMARKS_H
