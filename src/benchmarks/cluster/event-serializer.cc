// See the file "COPYING" in the main distribution directory for copyright.

#include <benchmark/benchmark.h>

#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/benchmarks/cluster/common.h"
#include "zeek/cluster/Event.h"
#include "zeek/cluster/serializer/broker/Serializer.h"
#include "zeek/cluster/serializer/sans-broker/Serializer.h"
#include "zeek/util-types.h"


namespace {

zeek::cluster::Event make_event_node_up() {
    auto eh = zeek::event_registry->Lookup("Cluster::node_up");

    zeek::Args args = {zeek::make_intrusive<zeek::StringVal>("worker-1"),
                       zeek::make_intrusive<zeek::StringVal>("ff8b006a-2df7-4161-9fc2-55a421fec9c7")};

    zeek::cluster::Event ev{eh, std::move(args), {}};
    return ev;
}

zeek::byte_buffer_span get_serialized_node_up() {
    static const char buf[] =
        "\016\003\002\000\000\000\000\000\000\000\001\002\000\000\000\000\000\000\000\001\016\002\005\020Cluster::node_"
        "up\016\002\005\010worker-1\005$ff8b006a-2df7-4161-9fc2-55a421fec9c7";

    return std::span{reinterpret_cast<const std::byte*>(buf), sizeof(buf) - 1};
}


void BM_Serialize_NodeUp_SansBroker(benchmark::State& state) {
    zeek::cluster::detail::SansBrokerBinV1_Serializer serializer;
    zeek::cluster::Event ev = make_event_node_up();

    for ( auto _ : state ) {
        zeek::byte_buffer buf;
        auto result = serializer.SerializeEvent(buf, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }

    // zeek::benchmark::dump_c_string(buf);
}

void BM_Serialize_NodeUp_Broker(benchmark::State& state) {
    zeek::cluster::detail::BrokerBinV1_Serializer serializer;
    zeek::cluster::Event ev = make_event_node_up();

    // This loop runs multiple times to get accurate measurements
    for ( auto _ : state ) {
        zeek::byte_buffer buf;
        auto result = serializer.SerializeEvent(buf, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(buf.data());
        if ( ! result || buf.empty() )
            abort();
    }

    // zeek::benchmark::dump_c_string(buf);
}

BENCHMARK(BM_Serialize_NodeUp_SansBroker);
BENCHMARK(BM_Serialize_NodeUp_Broker);

void BM_Unserialize_NodeUp_SansBroker(benchmark::State& state) {
    zeek::cluster::detail::SansBrokerBinV1_Serializer serializer;

    zeek::byte_buffer_span orig_span = get_serialized_node_up();

    for ( auto _ : state ) {
        auto result = serializer.UnserializeEvent(zeek::byte_buffer_span{orig_span});
        benchmark::DoNotOptimize(result);
        if ( ! result )
            abort();
    }
}

void BM_Unserialize_NodeUp_Broker(benchmark::State& state) {
    zeek::cluster::detail::BrokerBinV1_Serializer serializer;

    zeek::byte_buffer_span orig_span = get_serialized_node_up();

    for ( auto _ : state ) {
        auto result = serializer.UnserializeEvent(zeek::byte_buffer_span{orig_span});
        benchmark::DoNotOptimize(result);
        if ( ! result )
            abort();
    }
}


BENCHMARK(BM_Unserialize_NodeUp_SansBroker);
BENCHMARK(BM_Unserialize_NodeUp_Broker);

} // namespace

//
int main(int argc, char** argv) {
    // Fake setup.
    zeek::val_mgr = new zeek::ValManager();
    zeek::event_registry = new zeek::EventRegistry();
    zeek::reporter = new zeek::Reporter(false);

    zeek::EventHandler* eh = new zeek::EventHandler("Cluster::node_up");
    zeek::RecordTypePtr args_type = zeek::benchmark::get_string_string_args_type();

    auto ft = zeek::make_intrusive<zeek::FuncType>(args_type, nullptr, zeek::FUNC_FLAVOR_EVENT);
    auto sf = zeek::make_intrusive<zeek::detail::ScriptFunc>("Cluster::node_up", ft, std::vector<zeek::Func::Body>{});
    eh->SetFunc(sf);
    zeek::EventHandlerPtr ehptr{eh};
    zeek::event_registry->Register(ehptr);

    ::benchmark::Initialize(&argc, argv);
    if ( ::benchmark::ReportUnrecognizedArguments(argc, argv) )
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}
