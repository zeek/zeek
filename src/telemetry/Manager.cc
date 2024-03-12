// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#include <algorithm>
#include <thread>
#include <variant>

#include "zeek/3rdparty/doctest.h"
#include "zeek/ID.h"
#include "zeek/ZeekString.h"
#include "zeek/broker/Manager.h"
#include "zeek/telemetry/ProcessStats.h"
#include "zeek/telemetry/Timer.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "CivetServer.h"

namespace zeek::telemetry {

Manager::Manager() { prometheus_registry = std::make_shared<prometheus::Registry>(); }

Manager::~Manager() {}

void Manager::InitPostScript() {
    // Metrics port setting is used to calculate a URL for prometheus scraping
    std::string prometheus_url;
    if ( auto env = getenv("ZEEK_METRICS_PORT") )
        prometheus_url = util::fmt("localhost:%s", env);
    else {
        auto metrics_port = id::find_val("Telemetry::metrics_port")->AsPortVal();
        if ( metrics_port->Port() == 0 )
            // Remove this in v7.1 when the Broker variables are removed
            metrics_port = id::find_val("Broker::metrics_port")->AsPortVal();

        if ( metrics_port->Port() != 0 )
            prometheus_url = util::fmt("localhost:%u", metrics_port->Port());
    }

    if ( ! prometheus_url.empty() ) {
        printf("prometheus configured: %s\n", prometheus_url.c_str());

        CivetCallbacks* callbacks = nullptr;
        // if ( ! request_topic.empty() ) {
        //     callbacks = new CivetCallbacks();
        //     callbacks->begin_request = [](struct mg_connection* conn) -> int {
        //         printf("begin_request\n");
        //         // We only care about requests made to the /metrics endpoint. There are other request
        //         // made to the server that we can ignore, such as favicon.ico.
        //         auto req_info = mg_get_request_info(conn);
        //         if ( strcmp(req_info->request_uri, "/metrics") == 0 ) {
        //             // send a request to a topic for data from workers
        //             printf("posting event\n");
        //             broker_mgr->PublishEvent(telemetry_mgr->RequestTopic(), "Telemetry::remote_request",
        //                                      broker::vector{});

        //             // wait a few seconds for workers to respond
        //             // TODO: do we wait for all workers to respond or just go ahead and
        //             // respond after a few seconds with the understanding that some workers
        //             // might be out of date?
        //             // TODO: the 4 seconds here is completely arbitrary
        //             std::this_thread::sleep_for(std::chrono::seconds(4));
        //         }
        //         return 0;
        //     };
        // }

        prometheus_exposer = std::make_unique<prometheus::Exposer>(prometheus_url, 2, callbacks);
        prometheus_exposer->RegisterCollectable(prometheus_registry);
    }

#ifdef HAVE_PROCESS_STAT_METRICS
    static auto get_stats = [this]() -> const detail::process_stats* {
        double now = util::current_time();
        if ( this->process_stats_last_updated < now - 0.01 ) {
            this->current_process_stats = detail::get_process_stats();
            this->process_stats_last_updated = now;
        }

        return &this->current_process_stats;
    };
/*
    rss_gauge =
        GaugeInstance<int64_t>("process", "resident_memory", {}, "Resident memory size", "bytes", false,
                               [](metrics_api::ObserverResult r, void* state) {
                                   auto* s = get_stats();
                                   opentelemetry::nostd::get<
                                       opentelemetry::nostd::shared_ptr<metrics_api::ObserverResultT<int64_t>>>(r)
                                       ->Observe(s->rss);
                               });

    vms_gauge =
        GaugeInstance<int64_t>("process", "virtual_memory", {}, "Virtual memory size", "bytes", false,
                               [](metrics_api::ObserverResult r, void* state) {
                                   auto* s = get_stats();
                                   opentelemetry::nostd::get<
                                       opentelemetry::nostd::shared_ptr<metrics_api::ObserverResultT<int64_t>>>(r)
                                       ->Observe(s->vms);
                               });

    cpu_gauge = GaugeInstance<double>("process", "cpu", {}, "Total user and system CPU time spent", "seconds", false,
                                      [](metrics_api::ObserverResult r, void* state) {
                                          auto* s = get_stats();
                                          opentelemetry::nostd::get<
                                              opentelemetry::nostd::shared_ptr<metrics_api::ObserverResultT<double>>>(r)
                                              ->Observe(s->cpu);
                                      });

    fds_gauge =
        GaugeInstance<int64_t>("process", "open_fds", {}, "Number of open file descriptors", "", false,
                               [](metrics_api::ObserverResult r, void* state) {
                                   auto* s = get_stats();
                                   opentelemetry::nostd::get<
                                       opentelemetry::nostd::shared_ptr<metrics_api::ObserverResultT<int64_t>>>(r)
                                       ->Observe(s->fds);
                               });
*/
#endif
}

std::shared_ptr<MetricFamily> Manager::LookupFamily(std::string_view prefix, std::string_view name) const {
    auto check = [&](const auto& fam) { return fam.second->Prefix() == prefix && fam.second->Name() == name; };

    if ( auto it = std::find_if(families.begin(), families.end(), check); it != families.end() )
        return it->second;

    return nullptr;
}

// -- collect metric stuff -----------------------------------------------------

ValPtr Manager::CollectMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("any_vec");
    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Build a map of all of the families that match the patterns based on their full prefixed
    // name. This will let us match those families against the items returned from the otel reader.
    for ( const auto& [name, family] : families ) {
        // Histograms are handled by CollectHistogramMetrics and should be ignored here.
        if ( family->MetricType() == BifEnum::Telemetry::MetricType::INT_HISTOGRAM ||
             family->MetricType() == BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM )
            continue;

        if ( family->Matches(prefix_pattern, name_pattern) ) {
            auto records = family->Collect();
            for ( const auto& r : records )
                ret_val->Append(r);
        }
    }

    return ret_val;
}

ValPtr Manager::CollectHistogramMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("any_vec");
    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Build a map of all of the families that match the patterns based on their full prefixed
    // name. This will let us match those families against the items returned from the otel reader.
    for ( const auto& [name, family] : families ) {
        if ( family->MetricType() != BifEnum::Telemetry::MetricType::INT_HISTOGRAM &&
             family->MetricType() != BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM )
            continue;

        if ( family->Matches(prefix_pattern, name_pattern) ) {
            auto records = family->Collect();
            for ( const auto& r : records )
                ret_val->Append(r);
        }
    }

    return ret_val;
}

} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace std::literals;
using namespace zeek::telemetry;

namespace {

template<class T>
auto toVector(zeek::Span<T> xs) {
    std::vector<std::remove_const_t<T>> result;
    for ( auto&& x : xs )
        result.emplace_back(x);
    return result;
}

} // namespace

SCENARIO("telemetry managers provide access to counter families") {
    GIVEN("a telemetry manager") {
        Manager mgr;
        WHEN("retrieving an IntCounter family") {
            auto family = mgr.CounterFamily("zeek", "requests", {"method"}, "test", "1", true);
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "requests"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"method"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "1"sv);
                CHECK_EQ(family->IsSum(), true);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"method", "get"}});
                auto second = family->GetOrAdd({{"method", "get"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"method", "get"}});
                auto second = family->GetOrAdd({{"method", "put"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblCounter family") {
            auto family = mgr.CounterFamily<double>("zeek", "runtime", {"query"}, "test", "seconds", true);
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "runtime"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"query"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "seconds"sv);
                CHECK_EQ(family->IsSum(), true);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"query", "foo"}});
                auto second = family->GetOrAdd({{"query", "foo"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"query", "foo"}});
                auto second = family->GetOrAdd({{"query", "bar"}});
                CHECK_NE(first, second);
            }
        }
    }
}

SCENARIO("telemetry managers provide access to gauge families") {
    GIVEN("a telemetry manager") {
        Manager mgr;
        WHEN("retrieving an IntGauge family") {
            auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test", "1");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "open_connections"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "1"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "quic"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblGauge family") {
            auto family = mgr.GaugeFamily<double>("zeek", "water-level", {"river"}, "test", "meters");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "water_level"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"river"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "meters"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"river", "Sacramento"}});
                auto second = family->GetOrAdd({{"river", "Sacramento"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"query", "Sacramento"}});
                auto second = family->GetOrAdd({{"query", "San Joaquin"}});
                CHECK_NE(first, second);
            }
        }
    }
}

SCENARIO("telemetry managers provide access to histogram families") {
    GIVEN("a telemetry manager") {
        Manager mgr;
        WHEN("retrieving an IntHistogram family") {
            int64_t buckets[] = {10, 20};
            auto family = mgr.HistogramFamily("zeek", "payload-size", {"protocol"}, buckets, "test", "bytes");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "payload_size"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "bytes"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "udp"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblHistogram family") {
            double buckets[] = {10.0, 20.0};
            auto family = mgr.HistogramFamily<double>("zeek", "parse-time", {"protocol"}, buckets, "test", "seconds");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "parse_time"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "seconds"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "udp"}});
                CHECK_NE(first, second);
            }
            AND_THEN("Timers add observations to histograms") {
                auto hg = family->GetOrAdd({{"protocol", "tst"}});
                CHECK_EQ(hg->Sum(), 0.0);
                {
                    Timer observer{hg};
                    std::this_thread::sleep_for(1ms);
                }
                CHECK_NE(hg->Sum(), 0.0);
            }
        }
    }
}
