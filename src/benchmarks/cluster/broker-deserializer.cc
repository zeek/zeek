// See the file "COPYING" in the main distribution directory for copyright.

// Compare speed of Broker's val_to_data() + encode() steps with a Zeek-only
// reimplementation that works with Val directly.
#include <benchmark/benchmark.h>

#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/benchmarks/cluster/common.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/serializer/sans-broker/Serializer.h" // The re-implementation.

#include "broker/message.hh"


namespace {

zeek::ValPtr broker_deserialize(zeek::byte_buffer_span buf, const zeek::TypePtr& typ) {
    auto r = broker::data_envelope::deserialize(broker::endpoint_id::nil(), broker::endpoint_id::nil(), 0, "",
                                                buf.data(), buf.size());
    if ( ! r ) {
        std::fprintf(stderr, "Failed deserialize!\n");
        // std::fprintf(stderr, "%s\n", broker::to_string(r.error()).c_str());
        abort();
    }

    auto data = broker::get_data(*r).to_data();

    return zeek::Broker::detail::data_to_val(data, typ.get());
}

zeek::ValPtr sans_broker_deserialize(zeek::byte_buffer_span buf, const zeek::TypePtr& typ) {
    using zeek::cluster::format::broker::bin::v1::decode;
    return decode(buf, typ);
}

} // namespace

void BM_SingleCount_Broker(benchmark::State& state) {
    // Encoded count 42.
    std::vector<std::byte> buf = {
        std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2a},
    };

    auto typ = zeek::base_type(zeek::TYPE_COUNT);

    zeek::ValPtr result;

    for ( auto _ : state ) {
        result = broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result )
            abort();
    }

    // std::fprintf(stderr, "broker=%s\n", zeek::obj_desc_short(result).c_str());
}

void BM_SingleCount_SansBroker(benchmark::State& state) {
    // Encoded count 42.
    std::vector<std::byte> buf = {
        std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2a},
    };

    auto typ = zeek::base_type(zeek::TYPE_COUNT);

    zeek::ValPtr result;

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        result = sans_broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result )
            abort();
    }

    // std::fprintf(stderr, "zeek=%s\n", zeek::obj_desc_short(result).c_str());
}

BENCHMARK(BM_SingleCount_Broker);
BENCHMARK(BM_SingleCount_SansBroker);

void BM_VectorOfCount_Broker(benchmark::State& state) {
    auto buf = zeek::benchmark::get_vector_of_count_example();
    auto typ = zeek::benchmark::get_vector_of_count_type();

    zeek::ValPtr result;

    for ( auto _ : state ) {
        result = broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result )
            abort();
    }

    // std::fprintf(stderr, "broker=%s\n", zeek::obj_desc_short(result).c_str());
}

void BM_VectorOfCount_Zeek(benchmark::State& state) {
    auto buf = zeek::benchmark::get_vector_of_count_example();
    auto typ = zeek::benchmark::get_vector_of_count_type();

    zeek::ValPtr result;

    for ( auto _ : state ) {
        result = sans_broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result ) {
            std::fprintf(stderr, "failed to deserialize\n");
            abort();
        }
    }

    // std::fprintf(stderr, "zeek=%s\n", zeek::obj_desc_short(result).c_str());
}

BENCHMARK(BM_VectorOfCount_Broker);
BENCHMARK(BM_VectorOfCount_Zeek);

void BM_VectorOfString_Broker(benchmark::State& state) {
    auto buf = zeek::benchmark::get_vector_of_string_example();
    auto typ = zeek::benchmark::get_vector_of_string_type();

    zeek::ValPtr result;

    for ( auto _ : state ) {
        result = broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result )
            abort();
    }

    // std::fprintf(stderr, "broker=%s\n", zeek::obj_desc_short(result).c_str());
}

void BM_VectorOfString_SansBroker(benchmark::State& state) {
    auto buf = zeek::benchmark::get_vector_of_string_example();
    auto typ = zeek::benchmark::get_vector_of_string_type();

    zeek::ValPtr result;

    for ( auto _ : state ) {
        result = sans_broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result ) {
            std::fprintf(stderr, "failed to deserialize\n");
            abort();
        }
    }

    // std::fprintf(stderr, "zeek=%s\n", zeek::obj_desc_short(result).c_str());
}

BENCHMARK(BM_VectorOfString_Broker);
BENCHMARK(BM_VectorOfString_SansBroker);

void BM_Record_Broker(benchmark::State& state) {
    auto buf = zeek::benchmark::get_test_record_type_example();
    auto typ = zeek::benchmark::get_test_record_type();

    zeek::ValPtr result;

    for ( auto _ : state ) {
        result = broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result )
            abort();
    }

    // std::fprintf(stderr, "broker=%s\n", zeek::obj_desc_short(result).c_str());
}

void BM_Record_SansBroker(benchmark::State& state) {
    auto buf = zeek::benchmark::get_test_record_type_example();
    auto typ = zeek::benchmark::get_test_record_type();

    zeek::ValPtr result;

    for ( auto _ : state ) {
        result = sans_broker_deserialize(buf, typ);
        benchmark::DoNotOptimize(result);
        if ( ! result ) {
            std::fprintf(stderr, "failed to deserialize\n");
            abort();
        }
    }

    // std::fprintf(stderr, "zeek=%s\n", zeek::obj_desc_short(result).c_str());
}

BENCHMARK(BM_Record_Broker);
BENCHMARK(BM_Record_SansBroker);

//
int main(int argc, char** argv) {
    zeek::val_mgr = new zeek::ValManager();
    zeek::val_mgr->Count(42);

    ::benchmark::Initialize(&argc, argv);
    if ( ::benchmark::ReportUnrecognizedArguments(argc, argv) )
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
