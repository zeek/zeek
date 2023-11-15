// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#include <algorithm>
#include <thread>
#include <variant>

#include "zeek/3rdparty/doctest.h"
#include "zeek/ID.h"
#include "zeek/telemetry/OtelReader.h"
#include "zeek/telemetry/ProcessStats.h"
#include "zeek/telemetry/Timer.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/zeek-version.h"

#include "opentelemetry/exporters/ostream/metric_exporter_factory.h"
#include "opentelemetry/exporters/prometheus/exporter_factory.h"
#include "opentelemetry/exporters/prometheus/exporter_options.h"
#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader_factory.h"
#include "opentelemetry/sdk/metrics/meter.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/meter_provider_factory.h"
#include "opentelemetry/sdk/metrics/push_metric_exporter.h"
#include "opentelemetry/sdk/metrics/view/instrument_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/meter_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/view_factory.h"

namespace metrics_sdk = opentelemetry::sdk::metrics;
namespace common = opentelemetry::common;
namespace exportermetrics = opentelemetry::exporter::metrics;
namespace metrics_api = opentelemetry::metrics;

namespace zeek::telemetry {

enum MetricType { COUNTER, GAUGE, HISTOGRAM };

static metrics_sdk::AggregationType get_aggregation_type(const metrics_sdk::PointType& point_type) {
    if ( opentelemetry::nostd::holds_alternative<metrics_sdk::SumPointData>(point_type) ) {
        return metrics_sdk::AggregationType::kSum;
    }
    else if ( opentelemetry::nostd::holds_alternative<metrics_sdk::DropPointData>(point_type) ) {
        return metrics_sdk::AggregationType::kDrop;
    }
    else if ( opentelemetry::nostd::holds_alternative<metrics_sdk::HistogramPointData>(point_type) ) {
        return metrics_sdk::AggregationType::kHistogram;
    }
    else if ( opentelemetry::nostd::holds_alternative<metrics_sdk::LastValuePointData>(point_type) ) {
        return metrics_sdk::AggregationType::kLastValue;
    }

    return metrics_sdk::AggregationType::kDefault;
}

static MetricType get_metric_type(metrics_sdk::AggregationType agg_type, bool is_monotonic) {
    switch ( agg_type ) {
        case metrics_sdk::AggregationType::kSum:
            if ( ! is_monotonic ) {
                return MetricType::GAUGE;
            }
            else {
                return MetricType::COUNTER;
            }
            break;
        case metrics_sdk::AggregationType::kHistogram: return MetricType::HISTOGRAM;
        case metrics_sdk::AggregationType::kLastValue: return MetricType::GAUGE;
        default:
            // TODO: this should probably be a warning of some sort
            return MetricType::COUNTER;
    }
}

// Convert an int64_t or double to a DoubleValPtr. int64_t is casted.
template<typename T>
zeek::IntrusivePtr<zeek::DoubleVal> as_double_val(T val) {
    if constexpr ( std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t> ) {
        return zeek::make_intrusive<zeek::DoubleVal>(static_cast<double>(val));
    }
    else {
        static_assert(std::is_same_v<T, double>);
        return zeek::make_intrusive<zeek::DoubleVal>(val);
    }
};

static void set_record_values(const RecordValPtr& r, const metrics_sdk::ValueType& value, int value_idx,
                              int count_value_idx) {
    if ( opentelemetry::nostd::holds_alternative<double>(value) ) {
        r->Assign(value_idx, as_double_val(opentelemetry::nostd::get<double>(value)));
    }
    else if ( opentelemetry::nostd::holds_alternative<int64_t>(value) ) {
        int64_t v = opentelemetry::nostd::get<int64_t>(value);
        r->Assign(value_idx, as_double_val(v));
        r->Assign(count_value_idx, val_mgr->Count(v));
    }
}

template<typename T>
void build_observation(const std::map<std::pair<std::string, std::string>, T>& values,
                       opentelemetry::metrics::ObserverResult& result) {
    if ( opentelemetry::nostd::holds_alternative<
             opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<T>>>(result) ) {
        auto res =
            opentelemetry::nostd::get<opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<T>>>(
                result);

        for ( const auto& [k, v] : values ) {
            res->Observe(v, {k});
        }
    }
}

Manager::Manager()
    : metrics_name("zeek"), metrics_version(VERSION), metrics_schema("https://opentelemetry.io/schemas/1.2.0") {
    auto meter_provider = metrics_sdk::MeterProviderFactory::Create();
    auto* p = static_cast<metrics_sdk::MeterProvider*>(meter_provider.release());
    std::shared_ptr<metrics_api::MeterProvider> provider_sp(p);
    metrics_api::Provider::SetMeterProvider(provider_sp);
}

Manager::~Manager() {
    std::shared_ptr<opentelemetry::metrics::MeterProvider> none;
    metrics_api::Provider::SetMeterProvider(none);
}

void Manager::InitPostScript() {
    auto mp = metrics_api::Provider::GetMeterProvider();
    auto* p = static_cast<metrics_sdk::MeterProvider*>(mp.get());

    otel_reader = std::make_shared<OtelReader>();
    p->AddMetricReader(otel_reader);

    std::string prometheus_url;
    auto metrics_port = id::find_val("Broker::metrics_port")->AsPortVal();
    if ( metrics_port->Port() != 0 )
        prometheus_url = util::fmt("localhost:%u", metrics_port->Port());
    else if ( auto env = getenv("BROKER_METRICS_PORT") )
        prometheus_url = util::fmt("localhost:%s", env);

    if ( ! prometheus_url.empty() ) {
        opentelemetry::exporter::metrics::PrometheusExporterOptions exporter_options;
        exporter_options.url = prometheus_url;
        auto exporter = exportermetrics::PrometheusExporterFactory::Create(exporter_options);
        p->AddMetricReader(std::move(exporter));
    }

    if ( auto env = getenv("OTEL_DEBUG") ) {
        auto os_exporter = exportermetrics::OStreamMetricExporterFactory::Create();
        metrics_sdk::PeriodicExportingMetricReaderOptions options;
        options.export_interval_millis = std::chrono::milliseconds(1000);
        options.export_timeout_millis = std::chrono::milliseconds(500);
        auto reader = metrics_sdk::PeriodicExportingMetricReaderFactory::Create(std::move(os_exporter), options);
        p->AddMetricReader(std::move(reader));
    }

#ifdef HAVE_PROCESS_STAT_METRICS
    auto process_meter = p->GetMeter("process");
    static auto get_stats = [this]() -> const detail::process_stats* {
        double now = util::current_time();
        if ( this->process_stats_last_updated < now - 0.01 ) {
            this->current_process_stats = detail::get_process_stats();
            this->process_stats_last_updated = now;
        }

        return &this->current_process_stats;
    };

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

#endif
}

std::shared_ptr<MetricFamily> Manager::LookupFamily(std::string_view prefix, std::string_view name) const {
    auto check = [&](const auto& fam) { return fam->Prefix() == prefix && fam->Name() == name; };

    if ( auto it = std::find_if(families.begin(), families.end(), check); it != families.end() )
        return *it;

    return nullptr;
}

// -- collect metric stuff -----------------------------------------------------

ValPtr Manager::CollectMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    static auto opts_idx = metric_record_type->FieldOffset("opts");
    static auto labels_idx = metric_record_type->FieldOffset("labels");
    static auto value_idx = metric_record_type->FieldOffset("value");
    static auto count_value_idx = metric_record_type->FieldOffset("count_value");
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("any_vec");

    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Build a map of all of the families that match the patterns based on their full prefixed
    // name. This will let us match those families against the items returned from the otel reader.
    std::map<std::string, std::shared_ptr<MetricFamily>> matched_families;
    for ( const auto& family : families ) {
        if ( family->Matches(prefix_pattern, name_pattern) )
            matched_families.insert({family->FullName(), family});
    }

    if ( matched_families.empty() )
        return ret_val;

    auto results = otel_reader->Collect([&](metrics_sdk::ResourceMetrics& metric_data) {
        for ( const auto& instrumentation_info : metric_data.scope_metric_data_ ) {
            // Metric data = family
            for ( const auto& metric : instrumentation_info.metric_data_ ) {
                auto it = matched_families.find(metric.instrument_descriptor.name_);
                if ( it == matched_families.end() )
                    continue;

                RecordValPtr opts_record = it->second->GetMetricOptsRecord();

                // Point data = instrument
                for ( const auto& point_data_attr : metric.point_data_attr_ ) {
                    bool is_monotonic = true;
                    auto agg_type = get_aggregation_type(point_data_attr.point_data);
                    if ( agg_type == metrics_sdk::AggregationType::kSum )
                        is_monotonic = opentelemetry::nostd::get<metrics_sdk::SumPointData>(point_data_attr.point_data)
                                           .is_monotonic_;

                    auto metric_type = get_metric_type(agg_type, is_monotonic);
                    if ( metric_type == MetricType::HISTOGRAM )
                        continue;

                    auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
                    for ( const auto& [label_key, label] : point_data_attr.attributes )
                        label_values_vec->Append(make_intrusive<StringVal>(std::get<std::string>(label)));

                    auto r = make_intrusive<zeek::RecordVal>(metric_record_type);
                    r->Assign(labels_idx, label_values_vec);
                    r->Assign(opts_idx, opts_record);

                    if ( metric_type == MetricType::GAUGE ) {
                        if ( opentelemetry::nostd::holds_alternative<metrics_sdk::LastValuePointData>(
                                 point_data_attr.point_data) ) {
                            auto point_data =
                                opentelemetry::nostd::get<metrics_sdk::LastValuePointData>(point_data_attr.point_data);
                            std::vector<metrics_sdk::ValueType> values{point_data.value_};
                            set_record_values(r, values[0], value_idx, count_value_idx);
                        }
                        else if ( opentelemetry::nostd::holds_alternative<metrics_sdk::SumPointData>(
                                      point_data_attr.point_data) ) {
                            auto point_data =
                                opentelemetry::nostd::get<metrics_sdk::SumPointData>(point_data_attr.point_data);
                            std::vector<metrics_sdk::ValueType> values{point_data.value_};
                            set_record_values(r, values[0], value_idx, count_value_idx);
                        }
                    }
                    else {
                        auto point_data =
                            opentelemetry::nostd::get<metrics_sdk::SumPointData>(point_data_attr.point_data);
                        std::vector<metrics_sdk::ValueType> values{point_data.value_};
                        set_record_values(r, values[0], value_idx, count_value_idx);
                    }

                    ret_val->Append(r);
                }
            }
        }
        return true;
    });

    return ret_val;
}

ValPtr Manager::CollectHistogramMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
    static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");
    static auto histogram_metric_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
    static auto opts_idx = histogram_metric_type->FieldOffset("opts");
    static auto labels_idx = histogram_metric_type->FieldOffset("labels");
    static auto values_idx = histogram_metric_type->FieldOffset("values");
    static auto count_values_idx = histogram_metric_type->FieldOffset("count_values");
    static auto observations_idx = histogram_metric_type->FieldOffset("observations");

    static auto sum_idx = histogram_metric_type->FieldOffset("sum");
    static auto count_observations_idx = histogram_metric_type->FieldOffset("count_observations");
    static auto count_sum_idx = histogram_metric_type->FieldOffset("count_sum");

    static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto bounds_idx = opts_rt->FieldOffset("bounds");
    static auto count_bounds_idx = opts_rt->FieldOffset("count_bounds");

    static auto metrics_vector_type = zeek::id::find_type<VectorType>("any_vec");
    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Build a map of all of the families that match the patterns based on their full prefixed
    // name. This will let us match those families against the items returned from the otel reader.
    std::map<std::string, std::shared_ptr<MetricFamily>> matched_families;
    for ( const auto& family : families ) {
        if ( family->Matches(prefix_pattern, name_pattern) )
            matched_families.insert({family->FullName(), family});
    }

    if ( matched_families.empty() )
        return ret_val;

    auto results = otel_reader->Collect([&](metrics_sdk::ResourceMetrics& metric_data) {
        for ( const auto& instrumentation_info : metric_data.scope_metric_data_ ) {
            // Metric data = family
            for ( const auto& metric : instrumentation_info.metric_data_ ) {
                auto it = matched_families.find(metric.instrument_descriptor.name_);
                if ( it == matched_families.end() )
                    continue;

                RecordValPtr opts_record = it->second->GetMetricOptsRecord();

                // Point data = instrument
                for ( const auto& point_data_attr : metric.point_data_attr_ ) {
                    bool is_monotonic = true;
                    auto agg_type = get_aggregation_type(point_data_attr.point_data);
                    if ( agg_type == metrics_sdk::AggregationType::kSum )
                        is_monotonic = opentelemetry::nostd::get<metrics_sdk::SumPointData>(point_data_attr.point_data)
                                           .is_monotonic_;

                    auto metric_type = get_metric_type(agg_type, is_monotonic);
                    if ( metric_type != MetricType::HISTOGRAM )
                        continue;

                    auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
                    for ( const auto& [label_key, label] : point_data_attr.attributes )
                        label_values_vec->Append(make_intrusive<StringVal>(std::get<std::string>(label)));

                    auto r = make_intrusive<zeek::RecordVal>(histogram_metric_type);
                    r->Assign(labels_idx, label_values_vec);
                    r->Assign(opts_idx, opts_record);

                    auto histogram_point_data =
                        opentelemetry::nostd::get<metrics_sdk::HistogramPointData>(point_data_attr.point_data);
                    auto boundaries = histogram_point_data.boundaries_;
                    auto counts = histogram_point_data.counts_;

                    r->Assign(observations_idx, as_double_val(histogram_point_data.count_));

                    double sum = 0.0;
                    if ( opentelemetry::nostd::holds_alternative<double>(histogram_point_data.sum_) ) {
                        r->Assign(sum_idx, as_double_val(opentelemetry::nostd::get<double>(histogram_point_data.sum_)));
                    }
                    else {
                        int64_t v = opentelemetry::nostd::get<int64_t>(histogram_point_data.sum_);
                        r->Assign(sum_idx, as_double_val(v));
                        r->Assign(count_sum_idx, val_mgr->Count(v));
                        r->Assign(count_observations_idx, val_mgr->Count(histogram_point_data.count_));
                    }

                    RecordValPtr local_opts_record = r->GetField<RecordVal>(opts_idx);

                    // TODO: this needs to handle the int64_t version as well
                    auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
                    for ( auto val : boundaries )
                        bounds_vec->Append(as_double_val(val));
                    local_opts_record->Assign(bounds_idx, bounds_vec);

                    auto counts_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
                    for ( auto val : counts )
                        counts_vec->Append(as_double_val(val));
                    r->Assign(values_idx, counts_vec);

                    ret_val->Append(r);
                }
            }
        }
        return true;
    });

    return ret_val;
}

void Manager::AddView(const std::string& name, const std::string& helptext, const std::string& unit,
                      opentelemetry::sdk::metrics::InstrumentType instrument_type,
                      opentelemetry::sdk::metrics::AggregationType aggregation) {
    auto instrument_selector = metrics_sdk::InstrumentSelectorFactory::Create(instrument_type, name, unit);
    auto meter_selector = metrics_sdk::MeterSelectorFactory::Create(metrics_name, metrics_version, metrics_schema);
    auto view = metrics_sdk::ViewFactory::Create(name, helptext, unit, metrics_sdk::AggregationType::kHistogram);

    auto mp = metrics_api::Provider::GetMeterProvider();
    auto* p = static_cast<metrics_sdk::MeterProvider*>(mp.get());
    p->AddView(std::move(instrument_selector), std::move(meter_selector), std::move(view));
}

/**
 * Changes the frequency for publishing scraped metrics to the target topic.
 * Passing a zero-length interval has no effect.
 * @param value Interval between two scrapes in seconds.
 */
void Manager::SetMetricsExportInterval(double value) {}

/**
 * Sets a new target topic for the metrics. Passing an empty string has no
 * effect.
 * @param value The new topic for publishing local metrics to.
 */
void Manager::SetMetricsExportTopic(std::string value) {}

/**
 * Sets the import topics for a node importing metrics.
 *
 * @param topics List of topics from which to import metrics.
 */
void Manager::SetMetricsImportTopics(std::vector<std::string> topics) {}

/**
 * Sets a new ID for the metrics exporter. Passing an empty string has no
 * effect.
 * @param value The new ID of the exporter in published metrics.
 */
void Manager::SetMetricsExportEndpointName(std::string value) {}

/**
 * Sets a prefix selection for the metrics exporter. An empty vector selects
 * *all* metrics.
 * @param filter List of selected metric prefixes or an empty vector for
 *               selecting all metrics.
 */
void Manager::SetMetricsExportPrefixes(std::vector<std::string> filter) {}


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
            auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "open-connections"sv);
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
                CHECK_EQ(family->Name(), "water-level"sv);
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
                CHECK_EQ(family->Name(), "payload-size"sv);
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
                CHECK_EQ(family->Name(), "parse-time"sv);
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
