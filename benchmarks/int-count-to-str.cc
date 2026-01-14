// See the file "COPYING" in the main distribution directory for copyright.

#include <benchmark/benchmark.h>
#include <zeek/util.h>
#include <charconv>
#include <cstdio>

static void BM_litoa10(benchmark::State& state) {
    auto value = static_cast<zeek_int_t>(state.range(0));
    char buf[64] = {};

    for ( auto _ : state ) {
        size_t result = modp_litoa10(value, buf);
        if ( result > sizeof(buf) )
            std::exit(1);
    };
}

static void BM_ulitoa10(benchmark::State& state) {
    auto value = static_cast<zeek_uint_t>(state.range(0));
    char buf[64] = {};

    for ( auto _ : state ) {
        size_t result = modp_ulitoa10(value, buf);
        if ( result > sizeof(buf) )
            std::exit(1);
    };
};

static void BM_int_std_to_chars(benchmark::State& state) {
    auto value = static_cast<zeek_int_t>(state.range(0));
    char buf[64] = {};

    for ( auto _ : state ) {
        auto result = std::to_chars(&buf[0], &buf[sizeof(buf) - 1], value);
        if ( result.ec == std::errc::value_too_large )
            std::exit(1);
    };
};

static void BM_uint_std_to_chars(benchmark::State& state) {
    auto value = static_cast<zeek_uint_t>(state.range(0));
    char buf[64] = {};

    for ( auto _ : state ) {
        auto result = std::to_chars(&buf[0], &buf[sizeof(buf) - 1], value);
        if ( result.ec == std::errc::value_too_large )
            std::exit(1);
    };
};

constexpr int range_multiplier = 128;

BENCHMARK(BM_litoa10)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK(BM_ulitoa10)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK(BM_uint_std_to_chars)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK(BM_int_std_to_chars)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);

BENCHMARK_MAIN();
