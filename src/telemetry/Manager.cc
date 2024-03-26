// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#define RAPIDJSON_HAS_STDSTRING 1

// CivetServer is from the civetweb submodule in prometheus-cpp
#include <CivetServer.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
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
#include "zeek/threading/formatters/detail/json.h"

namespace zeek::telemetry {

Manager::Manager() { prometheus_registry = std::make_shared<prometheus::Registry>(); }

void Manager::InitPostScript() {
    // Metrics port setting is used to calculate a URL for prometheus scraping
    std::string prometheus_url;
    if ( auto env = getenv("ZEEK_METRICS_PORT") )
        prometheus_url = util::fmt("localhost:%s", env);
    else {
        auto metrics_port = id::find_val("Telemetry::metrics_port")->AsPortVal();
        if ( metrics_port->Port() != 0 )
            prometheus_url = util::fmt("localhost:%u", metrics_port->Port());
    }

    if ( ! prometheus_url.empty() ) {
        CivetCallbacks* callbacks = nullptr;
        auto local_node_name = id::find_val("Cluster::node")->AsStringVal();
        if ( local_node_name->Len() > 0 ) {
            auto cluster_nodes = id::find_val("Cluster::nodes")->AsTableVal();
            auto local_node = cluster_nodes->Find(IntrusivePtr<StringVal>{NewRef{}, local_node_name});
            auto local_node_type = local_node->AsRecordVal()->GetField<EnumVal>("node_type")->Get();

            static auto node_type_type = id::find_type("Cluster::NodeType")->AsEnumType();
            static auto manager_type = node_type_type->Lookup("Cluster", "MANAGER");

            if ( local_node_type == manager_type ) {
                callbacks = new CivetCallbacks();
                callbacks->begin_request = [](struct mg_connection* conn) -> int {
                    // Handle the services.json request ourselves by building up a response based on
                    // the cluster configuration.
                    auto req_info = mg_get_request_info(conn);
                    if ( strcmp(req_info->request_uri, "/services.json") == 0 ) {
                        // send a request to a topic for data from workers
                        auto json = telemetry_mgr->GetClusterJson();
                        mg_send_http_ok(conn, "application/json", static_cast<long long>(json.size()));
                        mg_write(conn, json.data(), json.size());
                        return 1;
                    }

                    return 0;
                };
            }
        }

        try {
            prometheus_exposer = std::make_unique<prometheus::Exposer>(prometheus_url, 2, callbacks);
        } catch ( const CivetException& exc ) {
            reporter->FatalError("Failed to setup Prometheus endpoint: %s\n", exc.what());
        }

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
    rss_gauge = GaugeInstance<int64_t>("process", "resident_memory", {}, "Resident memory size", "bytes", false,
                                       []() -> prometheus::ClientMetric {
                                           auto* s = get_stats();
                                           prometheus::ClientMetric metric;
                                           metric.gauge.value = static_cast<double>(s->rss);
                                           return metric;
                                       });

    vms_gauge = GaugeInstance<int64_t>("process", "virtual_memory", {}, "Virtual memory size", "bytes", false,
                                       []() -> prometheus::ClientMetric {
                                           auto* s = get_stats();
                                           prometheus::ClientMetric metric;
                                           metric.gauge.value = static_cast<double>(s->vms);
                                           return metric;
                                       });

    cpu_gauge = GaugeInstance<double>("process", "cpu", {}, "Total user and system CPU time spent", "seconds", false,
                                      []() -> prometheus::ClientMetric {
                                          auto* s = get_stats();
                                          prometheus::ClientMetric metric;
                                          metric.gauge.value = s->cpu;
                                          return metric;
                                      });

    fds_gauge = GaugeInstance<int64_t>("process", "open_fds", {}, "Number of open file descriptors", "", false,
                                       []() -> prometheus::ClientMetric {
                                           auto* s = get_stats();
                                           prometheus::ClientMetric metric;
                                           metric.gauge.value = static_cast<double>(s->fds);
                                           return metric;
                                       });
#endif
}

// -- collect metric stuff -----------------------------------------------------

RecordValPtr Manager::GetMetricOptsRecord(const prometheus::MetricFamily& metric_family) {
    // Avoid recreating this repeatedly
    if ( auto it = opts_records.find(metric_family.name); it != opts_records.end() )
        return it->second;

    // Get the opt record
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");

    static auto prefix_idx = metric_opts_type->FieldOffset("prefix");
    static auto name_idx = metric_opts_type->FieldOffset("name");
    static auto help_text_idx = metric_opts_type->FieldOffset("help_text");
    static auto unit_idx = metric_opts_type->FieldOffset("unit");
    static auto labels_idx = metric_opts_type->FieldOffset("labels");
    static auto is_total_idx = metric_opts_type->FieldOffset("is_total");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    auto record_val = make_intrusive<zeek::RecordVal>(metric_opts_type);
    record_val->Assign(name_idx, make_intrusive<zeek::StringVal>(metric_family.name));
    record_val->Assign(help_text_idx, make_intrusive<zeek::StringVal>(metric_family.help));

    // prometheus-cpp doesn't store the prefix information separately. we pull the word
    // before the first underscore as the prefix instead. The Prometheus docs state
    // that the prefix "should exist" not "must exist" so it's possible this could result
    // in incorrect data, but it should be correct for all of our uses.
    std::string prefix;
    auto first_underscore = metric_family.name.find('_');
    if ( first_underscore != std::string::npos )
        prefix = metric_family.name.substr(0, first_underscore);

    record_val->Assign(prefix_idx, make_intrusive<zeek::StringVal>(prefix));

    // Assume that a metric ending with _total is always a summed metric so we can set that.
    record_val->Assign(is_total_idx, val_mgr->Bool(util::ends_with(metric_family.name, "_total")));

    auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);

    // Check if this is a Zeek-internal metric. We keep a little more information about a metric
    // for these than we do for ones that were inserted into prom-cpp directly.
    if ( auto it = families.find(metric_family.name); it != families.end() ) {
        record_val->Assign(metric_type_idx,
                           zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(it->second->MetricType()));

        for ( const auto& lbl : it->second->LabelNames() )
            label_names_vec->Append(make_intrusive<StringVal>(lbl));
    }
    else {
        // prom-cpp stores everything internally as doubles
        if ( metric_family.type == prometheus::MetricType::Counter )
            record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                    BifEnum::Telemetry::MetricType::DOUBLE_COUNTER));
        if ( metric_family.type == prometheus::MetricType::Gauge )
            record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                    BifEnum::Telemetry::MetricType::DOUBLE_GAUGE));
        if ( metric_family.type == prometheus::MetricType::Histogram )
            record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                    BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM));

        // prom-cpp doesn't store label names anywhere other than in each instrument. just assume
        // they're always going to be the same across all of the instruments and use the names from
        // the first one.
        // TODO: is this check here ever false?
        if ( ! metric_family.metric.empty() )
            for ( const auto& lbl : metric_family.metric[0].label )
                label_names_vec->Append(make_intrusive<StringVal>(lbl.name));
    }

    record_val->Assign(labels_idx, label_names_vec);

    opts_records.insert({metric_family.name, record_val});

    return record_val;
}

ValPtr Manager::CollectMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("any_vec");
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    static auto opts_idx = metric_record_type->FieldOffset("opts");
    static auto labels_idx = metric_record_type->FieldOffset("labels");
    static auto value_idx = metric_record_type->FieldOffset("value");
    static auto count_value_idx = metric_record_type->FieldOffset("count_value");

    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Due to the name containing the full information about a metric including a potential unit add an
    // asterisk to the end of the full pattern so matches work correctly.
    std::string full_pattern = util::fmt("%s_%s", prefix_pattern.data(), name_pattern.data());
    if ( full_pattern[full_pattern.size() - 1] != '*' )
        full_pattern.append("*");

    auto collected = prometheus_registry->Collect();
    for ( const auto& fam : collected ) {
        if ( fam.type == prometheus::MetricType::Histogram )
            continue;

        if ( fnmatch(full_pattern.c_str(), fam.name.c_str(), 0) == FNM_NOMATCH )
            continue;

        RecordValPtr opts_record = GetMetricOptsRecord(fam);

        for ( const auto& inst : fam.metric ) {
            auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
            for ( const auto& label : inst.label ) {
                // We don't include the endpoint key/value unless it's a prometheus request
                if ( label.name != "endpoint" )
                    label_values_vec->Append(make_intrusive<StringVal>(label.value));
            }

            auto r = make_intrusive<zeek::RecordVal>(metric_record_type);
            r->Assign(labels_idx, label_values_vec);
            r->Assign(opts_idx, opts_record);

            if ( fam.type == prometheus::MetricType::Counter )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(inst.counter.value));
            else if ( fam.type == prometheus::MetricType::Gauge )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(inst.gauge.value));

            // Use the information from GetMetaricOptsRecord to check whether we need to add the integer
            // fields, or if this is a double.
            if ( opts_record->GetField<EnumVal>(metric_type_idx)->Get() ==
                 BifEnum::Telemetry::MetricType::INT_COUNTER ) {
                r->Assign(count_value_idx, val_mgr->Count(static_cast<int64_t>(inst.counter.value)));
            }
            else if ( opts_record->GetField<EnumVal>(metric_type_idx)->Get() ==
                      BifEnum::Telemetry::MetricType::INT_GAUGE ) {
                r->Assign(count_value_idx, val_mgr->Count(static_cast<int64_t>(inst.gauge.value)));
            }

            ret_val->Append(r);
        }
    }

    return ret_val;
}

ValPtr Manager::CollectHistogramMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("any_vec");
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
    static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");
    static auto histogram_metric_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
    static auto labels_idx = histogram_metric_type->FieldOffset("labels");
    static auto values_idx = histogram_metric_type->FieldOffset("values");
    static auto count_values_idx = histogram_metric_type->FieldOffset("count_values");

    static auto observations_idx = histogram_metric_type->FieldOffset("observations");
    static auto count_observations_idx = histogram_metric_type->FieldOffset("count_observations");

    static auto sum_idx = histogram_metric_type->FieldOffset("sum");
    static auto count_sum_idx = histogram_metric_type->FieldOffset("count_sum");

    static auto opts_idx = histogram_metric_type->FieldOffset("opts");
    static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto bounds_idx = opts_rt->FieldOffset("bounds");
    static auto count_bounds_idx = opts_rt->FieldOffset("count_bounds");

    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Due to the name containing the full information about a metric including a potential unit add an
    // asterisk to the end of the full pattern so matches work correctly.
    std::string full_pattern = util::fmt("%s_%s", prefix_pattern.data(), name_pattern.data());
    if ( full_pattern[full_pattern.size() - 1] != '*' )
        full_pattern.append("*");

    auto collected = prometheus_registry->Collect();
    for ( const auto& fam : collected ) {
        if ( fam.type != prometheus::MetricType::Histogram )
            continue;

        if ( fnmatch(full_pattern.c_str(), fam.name.c_str(), 0) == FNM_NOMATCH )
            continue;

        RecordValPtr opts_record = GetMetricOptsRecord(fam);

        for ( const auto& inst : fam.metric ) {
            auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
            for ( const auto& label : inst.label ) {
                // We don't include the endpoint key/value unless it's a prometheus request
                if ( label.name != "endpoint" )
                    label_values_vec->Append(make_intrusive<StringVal>(label.value));
            }

            auto r = make_intrusive<zeek::RecordVal>(histogram_metric_type);
            r->Assign(labels_idx, label_values_vec);
            r->Assign(opts_idx, opts_record);

            auto double_values_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            auto count_values_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
            std::vector<double> boundaries;
            uint64_t last = 0.0;
            for ( const auto& b : inst.histogram.bucket ) {
                double_values_vec->Append(
                    zeek::make_intrusive<DoubleVal>(static_cast<double>(b.cumulative_count - last)));
                count_values_vec->Append(val_mgr->Count(b.cumulative_count - last));
                last = b.cumulative_count;
                boundaries.push_back(b.upper_bound);
            }

            // TODO: these could be stored somehow to avoid recreating them repeatedly
            auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            auto count_bounds_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
            for ( auto b : boundaries ) {
                bounds_vec->Append(zeek::make_intrusive<DoubleVal>(b));

                // The boundaries from prom-cpp include the infinite boundary in double.
                // This can't be converted safely to int64_t, so check for that case and
                // set the int64_t version.
                if ( b != std::numeric_limits<double>::infinity() )
                    count_bounds_vec->Append(val_mgr->Count(static_cast<int64_t>(b)));
                else
                    count_bounds_vec->Append(val_mgr->Count(std::numeric_limits<int64_t>::infinity()));
            }

            r->Assign(values_idx, double_values_vec);
            r->Assign(observations_idx,
                      zeek::make_intrusive<DoubleVal>(static_cast<double>(inst.histogram.sample_count)));
            r->Assign(sum_idx, zeek::make_intrusive<DoubleVal>(inst.histogram.sample_sum));

            RecordValPtr local_opts_record = r->GetField<RecordVal>(opts_idx);
            local_opts_record->Assign(bounds_idx, bounds_vec);

            // Use the information from GetMetaricOptsRecord to check whether we need to add the integer
            // fields, or if this is a double.
            if ( opts_record->GetField<EnumVal>(metric_type_idx)->Get() ==
                 BifEnum::Telemetry::MetricType::INT_HISTOGRAM ) {
                r->Assign(count_values_idx, count_values_vec);
                r->Assign(count_observations_idx, val_mgr->Count(inst.histogram.sample_count));
                r->Assign(count_sum_idx, val_mgr->Count(static_cast<int64_t>(inst.histogram.sample_sum)));
                local_opts_record->Assign(count_bounds_idx, count_bounds_vec);
            }

            ret_val->Append(r);
        }
    }

    return ret_val;
}

std::string Manager::GetClusterJson() const {
    rapidjson::StringBuffer buffer;
    json::detail::NullDoubleWriter writer(buffer);

    writer.StartArray();
    writer.StartObject();

    writer.Key("targets");
    writer.StartArray();
    auto cluster_nodes = id::find_val("Cluster::nodes")->AsTableVal()->ToMap();
    for ( const auto& [idx, value] : cluster_nodes ) {
        auto node = value->AsRecordVal();
        auto ip = node->GetField<AddrVal>("ip");
        auto port = node->GetField<PortVal>("metrics_port");
        if ( ip && port && port->Port() != 0 )
            writer.String(util::fmt("%s:%d", ip->Get().AsString().c_str(), port->Port()));
    }
    writer.EndArray();

    writer.Key("labels");
    writer.StartObject();
    writer.EndObject();

    writer.EndObject();
    writer.EndArray();

    return buffer.GetString();
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
            auto family = mgr.CounterFamily("zeek", "requests", {"method"}, "test", "", true);
            THEN("GetOrAdd returns the same metric for the same labels") {
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
            THEN("GetOrAdd returns the same metric for the same labels") {
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
            auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test", "");
            THEN("GetOrAdd returns the same metric for the same labels") {
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
            THEN("GetOrAdd returns the same metric for the same labels") {
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
            THEN("GetOrAdd returns the same metric for the same labels") {
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
            THEN("GetOrAdd returns the same metric for the same labels") {
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
