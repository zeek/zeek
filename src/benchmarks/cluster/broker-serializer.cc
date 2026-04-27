// See the file "COPYING" in the main distribution directory for copyright.

#include <benchmark/benchmark.h>

#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/benchmarks/cluster/common.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/serializer/sans-broker/Serializer.h" // The re-implementation.

#include "ZeekString.h"
#include "broker/format/bin.hh"


namespace {

bool broker_serialize(zeek::byte_buffer& buf, const zeek::ValPtr& v) {
    auto bval = zeek::Broker::detail::val_to_data(v.get());
    if ( ! bval.has_value() )
        return false;

    buf.resize(0);
    broker::format::bin::v1::encode(*bval, std::back_inserter(buf));
    return true;
}

bool sans_broker_serialize(zeek::byte_buffer& buf, const zeek::ValPtr& v) {
    using zeek::cluster::format::broker::bin::v1::encode;

    buf.resize(0);
    return encode(*v, std::back_inserter(buf));
}

void BM_SingleCount_Broker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto forty_two = zeek::val_mgr->Count(42);

    for ( auto _ : state ) {
        auto result = broker_serialize(buf, forty_two);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( buf.empty() )
            abort();
    }
}

void BM_SingleCount_SansBroker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto forty_two = zeek::val_mgr->Count(42);

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        auto result = sans_broker_serialize(buf, forty_two);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }
}

BENCHMARK(BM_SingleCount_Broker);
BENCHMARK(BM_SingleCount_SansBroker);

void BM_VectorOfCount_Broker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto vv = zeek::make_intrusive<zeek::VectorVal>(zeek::benchmark::get_vector_of_count_type());
    vv->Append(zeek::val_mgr->Count(42));
    vv->Append(zeek::val_mgr->Count(4711));

    for ( auto _ : state ) {
        auto result = broker_serialize(buf, vv);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( buf.empty() )
            abort();
    }
}

void BM_VectorOfCount_SansBroker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto vv = zeek::make_intrusive<zeek::VectorVal>(zeek::benchmark::get_vector_of_count_type());
    vv->Append(zeek::val_mgr->Count(42));
    vv->Append(zeek::val_mgr->Count(4711));

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        auto result = sans_broker_serialize(buf, vv);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }

    // zeek::benchmark::dump_c_string(buf);
}

BENCHMARK(BM_VectorOfCount_Broker);
BENCHMARK(BM_VectorOfCount_SansBroker);


void BM_VectorOfString_Broker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto vv = zeek::benchmark::get_vector_of_string_val();

    for ( auto _ : state ) {
        auto result = broker_serialize(buf, vv);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( buf.empty() )
            abort();
    }
}

void BM_VectorOfString_SansBroker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto vv = zeek::benchmark::get_vector_of_string_val();

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        auto result = sans_broker_serialize(buf, vv);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }
}

BENCHMARK(BM_VectorOfString_Broker);
BENCHMARK(BM_VectorOfString_SansBroker);

zeek::RecordValPtr make_record_val() {
    auto rt = zeek::benchmark::get_test_record_type();

    auto rv = zeek::make_intrusive<zeek::RecordVal>(rt);
    rv->Assign(0, 42);


    rv->Assign(1, zeek::make_intrusive<zeek::StringVal>("Forty Two is magic! 4711 is also funny."));

    rv->AssignTime(2, 1777219693.1234567);
    rv->AssignInterval(3, 42.0);

    auto vv1 = zeek::make_intrusive<zeek::VectorVal>(zeek::cast_intrusive<zeek::VectorType>(rt->GetFieldType(4)));
    vv1->Append(zeek::make_intrusive<zeek::CountVal>(42));
    vv1->Append(zeek::make_intrusive<zeek::CountVal>(4711));
    rv->Assign(4, std::move(vv1));

    return rv;
}

void BM_Record_Broker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto record = make_record_val();

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        auto result = broker_serialize(buf, record);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }

    // zeek::benchmark::dump_c_string(buf);
}

void BM_Record_SansBroker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto record = make_record_val();

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        auto result = sans_broker_serialize(buf, record);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }

    // std::fprintf(stderr, "Zeek size=%zu\n", buf.size());
    // std::fprintf(stderr, "Zeek rec=%s\n", zeek::obj_desc(record).c_str());
}


BENCHMARK(BM_Record_Broker);
BENCHMARK(BM_Record_SansBroker);

zeek::TableValPtr make_table_val() {
    zeek::TypeListPtr tl1 = zeek::make_intrusive<zeek::TypeList>(zeek::base_type(zeek::TYPE_COUNT));
    tl1->Append(zeek::base_type(zeek::TYPE_COUNT));
    auto st = zeek::make_intrusive<zeek::TableType>(std::move(tl1), nullptr);

    zeek::TypeListPtr tl2 = zeek::make_intrusive<zeek::TypeList>();
    tl2->Append(zeek::base_type(zeek::TYPE_STRING));
    tl2->Append(zeek::base_type(zeek::TYPE_STRING));

    // table[string, string] of set[count].
    auto tt = zeek::make_intrusive<zeek::TableType>(tl2, st);

    auto sv = zeek::make_intrusive<zeek::TableVal>(st);
    sv->Assign(zeek::val_mgr->Count(42), nullptr);
    sv->Assign(zeek::val_mgr->Count(4711), nullptr);

    auto tv = zeek::make_intrusive<zeek::TableVal>(tt);

    auto key1 = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_STRING);
    key1->Append(zeek::make_intrusive<zeek::StringVal>("42"));
    key1->Append(zeek::make_intrusive<zeek::StringVal>("forty-two"));
    auto key2 = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_STRING);
    key2->Append(zeek::make_intrusive<zeek::StringVal>("4711"));
    key2->Append(zeek::make_intrusive<zeek::StringVal>("four-seven-eleven"));


    tv->Assign(key1, sv);
    tv->Assign(key2, sv);

    // std::fprintf(stderr, "tv=%s\n", zeek::obj_desc_short(tv).c_str());
    return tv;
}

void BM_TableSet_Broker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto record = make_table_val();

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        auto result = broker_serialize(buf, record);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }

    // std::fprintf(stderr, "Broker size=%zu\n", buf.size());
}
void BM_TableSet_SansBroker(benchmark::State& state) {
    zeek::byte_buffer buf;

    auto record = make_table_val();

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        auto result = sans_broker_serialize(buf, record);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }

    // std::fprintf(stderr, "Zeek size=%zu\n", buf.size());
    // std::fprintf(stderr, "Zeek rec=%s\n", zeek::obj_desc(record).c_str());
}

BENCHMARK(BM_TableSet_Broker);
BENCHMARK(BM_TableSet_SansBroker);

} // namespace


//
int main(int argc, char** argv) {
    zeek::val_mgr = new zeek::ValManager();

    ::benchmark::Initialize(&argc, argv);
    if ( ::benchmark::ReportUnrecognizedArguments(argc, argv) )
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
