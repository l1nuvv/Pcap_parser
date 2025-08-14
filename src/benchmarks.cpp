#include "benchmarks.h"


using steady_clock_t = std::chrono::steady_clock;

long long benchmark_std_sort(const std::map<uint32_t, uint32_t> &length_stats)
{
    steady_clock_t::time_point start_sort;
    steady_clock_t::time_point end_sort;
    long long                  duration_sort = 0;
    const int                  trials        = 50;

    for (int t = 0; t < trials; ++t) {
        std::vector<std::pair<uint32_t, uint32_t>> temp;
        temp.reserve(length_stats.size());
        for (auto it = length_stats.begin(); it != length_stats.end(); ++it) {
            temp.push_back(std::make_pair(it->first, it->second));
        }

        std::random_shuffle(temp.begin(), temp.end());

        start_sort = steady_clock_t::now();
        std::sort(temp.begin(), temp.end(),
                  [](const std::pair<uint32_t, uint32_t> &a, const std::pair<uint32_t, uint32_t> &b) {
                      if (a.second != b.second) { return a.second < b.second; }
                      return a.first < b.first;
                  });
        end_sort = steady_clock_t::now();
        duration_sort += std::chrono::duration_cast<std::chrono::microseconds>(end_sort - start_sort).count();
    }

    return duration_sort / trials;
}

long long benchmark_multimap(const std::map<uint32_t, uint32_t> &length_stats)
{
    steady_clock_t::time_point        start_multimap = steady_clock_t::now();
    std::multimap<uint32_t, uint32_t> count_to_length;
    for (auto it = length_stats.begin(); it != length_stats.end(); ++it) {
        count_to_length.insert(std::make_pair(it->second, it->first));
    }
    steady_clock_t::time_point end_multimap = steady_clock_t::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(end_multimap - start_multimap).count();
}
