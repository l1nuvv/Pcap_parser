#include "benchmarks.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <random>
#include <vector>

long long benchmark_std_sort(const std::map<uint32_t, uint32_t> &length_stats)
{
    long long    duration_sort = 0;
    std::mt19937 rng(123456789);

    if (length_stats.empty()) return 0;

    for (int t = 0; t < pcap_constants::TRIALS; ++t) {
        std::vector<std::pair<uint32_t, uint32_t>> temp;
        temp.reserve(length_stats.size());

        for (const auto &length_stat: length_stats) {
            temp.emplace_back(length_stat.first, length_stat.second);
        }

        std::shuffle(temp.begin(), temp.end(), rng);

        auto start_sort = steady_clock_t::now();

        std::sort(temp.begin(), temp.end(),
                  [](const std::pair<uint32_t, uint32_t> &a, const std::pair<uint32_t, uint32_t> &b) {
                      if (a.second != b.second) return a.second < b.second;
                      return a.first < b.first;
                  });

        auto end_sort = steady_clock_t::now();

        duration_sort += std::chrono::duration_cast<std::chrono::microseconds>(end_sort - start_sort).count();

        volatile uint64_t sink = 0;
        for (const auto &p: temp) {
            sink += p.first + p.second;
        }
        (void) sink;
    }

    return duration_sort / pcap_constants::TRIALS;
}

long long benchmark_multimap(const std::map<uint32_t, uint32_t> &length_stats)
{
    long long total_us = 0;

    if (length_stats.empty()) return 0;

    for (int t = 0; t < pcap_constants::TRIALS; ++t) {
        auto start = steady_clock_t::now();

        std::multimap<std::pair<uint32_t, uint32_t>, uint8_t> mm;

        for (const auto &length_stat: length_stats) {
            mm.emplace(std::make_pair(length_stat.second, length_stat.first), 0);
        }

        auto end = steady_clock_t::now();

        total_us += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        volatile uint32_t sink = 0;
        sink += static_cast<uint32_t>(mm.size());
        (void) sink;
    }

    return total_us / pcap_constants::TRIALS;
}
