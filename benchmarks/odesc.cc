// See the file "COPYING" in the main distribution directory for copyright.

#include <benchmark/benchmark.h>
#include <zeek/Desc.h>
#include <cstdio>

constexpr double wiggle = 0.321321;

static void ODesc_Add_double(benchmark::State& state) {
    zeek::ODesc d;
    double value = static_cast<double>(state.range(0)) + wiggle;

    for ( auto _ : state ) {
        d.Add(value);
        d.Clear();
    };
}

constexpr int range_multiplier = 128;
BENCHMARK(ODesc_Add_double)->RangeMultiplier(range_multiplier)->Range(0, 1768397792);
BENCHMARK_MAIN();
