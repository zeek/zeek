// See the file "COPYING" in the main distribution directory for copyright.

#include <benchmark/benchmark.h>
#include <zeek/util.h>
#include <charconv>
#include <cstdio>

constexpr double wiggle = 0.321321;

static void BM_double_snprintf(benchmark::State& state) {
    double value = static_cast<double>(state.range(0)) + wiggle;
    char buf[64] = {};

    for ( auto _ : state ) {
        size_t result = std::snprintf(buf, sizeof(buf), "%.6f", value);
        if ( result > sizeof(buf) )
            std::exit(1);
    };
}

static void BM_double_modp_dtoa(benchmark::State& state) {
    double value = static_cast<double>(state.range(0)) + wiggle;
    char buf[64] = {};

    for ( auto _ : state ) {
        size_t result = modp_dtoa(value, buf, 6);
        if ( result > sizeof(buf) )
            std::exit(1);
    };
};

static void BM_double_std_to_chars(benchmark::State& state) {
    double value = static_cast<double>(state.range(0)) + wiggle;

    for ( auto _ : state ) {
        std::string result = zeek::util::double_to_str(value, 6, /*no_exp=*/true);
        if ( result.empty() )
            std::exit(1);
    };
};

static void BM_double_std_to_chars2(benchmark::State& state) {
    double value = static_cast<double>(state.range(0)) + wiggle;

    char tmp[350];
    for ( auto _ : state ) {
        auto result = zeek::util::double_to_str2(value, tmp, sizeof(tmp), 6, /*no_exp=*/true);
        if ( result == 0 )
            std::exit(1);
    };
};

static void BM_double_raw_std_to_chars_fixed(benchmark::State& state) {
    double value = static_cast<double>(state.range(0)) + wiggle;
    char buf[64] = {};

    for ( auto _ : state ) {
        auto result = std::to_chars(&buf[0], &buf[sizeof(buf) - 1], value, std::chars_format::fixed, 6);
        if ( result.ec == std::errc::value_too_large )
            std::exit(1);
    };
};

constexpr int range_multiplier = 128;

BENCHMARK(BM_double_snprintf)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK(BM_double_modp_dtoa)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK(BM_double_std_to_chars)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK(BM_double_std_to_chars2)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK(BM_double_raw_std_to_chars_fixed)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK_MAIN();
