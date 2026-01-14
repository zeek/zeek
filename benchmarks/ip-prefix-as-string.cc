// See the file "COPYING" in the main distribution directory for copyright.

#include <benchmark/benchmark.h>
#include <zeek/IPAddr.h>
#include <cstdio>

static void IPPrefix4_AsString(benchmark::State& state) {
    double value = 42.0;
    char buf[64] = {};

    zeek::IPPrefix prefix;
    if ( ! zeek::IPPrefix::ConvertString("192.168.0.1/24", &prefix) )
        std::exit(1);

    for ( auto _ : state ) {
        std::string result = prefix.AsString();
        if ( result.empty() )
            std::exit(1);
    };
}

static void IPPrefix6_AsString(benchmark::State& state) {
    double value = 42.0;
    char buf[64] = {};

    zeek::IPPrefix prefix;
    if ( ! zeek::IPPrefix::ConvertString("2a02:8108:be91:4932:a93:c711:69e:465/64", &prefix) )
        std::exit(1);

    for ( auto _ : state ) {
        std::string result = prefix.AsString();
        if ( result.empty() )
            std::exit(1);
    };
}

BENCHMARK(IPPrefix4_AsString);
BENCHMARK(IPPrefix6_AsString);
BENCHMARK_MAIN();
