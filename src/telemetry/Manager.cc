// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#include <fnmatch.h>
#include <thread>
#include <variant>

#include "zeek/3rdparty/doctest.h"
#include "zeek/ID.h"
#include "zeek/broker/Manager.h"
#include "zeek/telemetry/Timer.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/zeek-version.h"

#include "broker/telemetry/metric_registry.hh"
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

namespace {
using NativeManager = broker::telemetry::metric_registry;
using NativeManagerImpl = broker::telemetry::metric_registry_impl;
using NativeManagerImplPtr = zeek::IntrusivePtr<NativeManagerImpl>;
using DoubleValPtr = zeek::IntrusivePtr<zeek::DoubleVal>;

std::vector<std::string_view> extract_label_values(broker::telemetry::const_label_list labels) {
    auto get_value = [](const auto& label) { return label.second; };
    std::vector<std::string_view> v;
    std::transform(labels.begin(), labels.end(), std::back_inserter(v), get_value);
    return v;
}

// Convert an int64_t or double to a DoubleValPtr. int64_t is casted.
template<typename T>
DoubleValPtr as_double_val(T val) {
    if constexpr ( std::is_same_v<T, int64_t> ) {
        return zeek::make_intrusive<zeek::DoubleVal>(static_cast<double>(val));
    }
    else {
        static_assert(std::is_same_v<T, double>);
        return zeek::make_intrusive<zeek::DoubleVal>(val);
    }
};

} // namespace

namespace zeek::telemetry {

Manager::Manager()
    : metrics_name("zeek"), metrics_version(VERSION), metrics_schema("https://opentelemetry.io/schemas/1.2.0") {
    auto reg = NativeManager::pre_init_instance();
    NativeManagerImplPtr ptr{NewRef{}, reg.pimpl()};
    pimpl.swap(ptr);

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

    // Counter view
    // TODO: I'm not sure these do anything for us. At the very least, they don't match any
    // of our metric names, and we'd have to make a view for each one of them.
    std::string counter_name = metrics_name + "_counter";
    auto instrument_selector =
        metrics_sdk::InstrumentSelectorFactory::Create(metrics_sdk::InstrumentType::kCounter, counter_name, "");
    auto meter_selector = metrics_sdk::MeterSelectorFactory::Create(metrics_name, metrics_version, metrics_schema);
    auto sum_view =
        metrics_sdk::ViewFactory::Create(metrics_name, "description", "", metrics_sdk::AggregationType::kSum);
    p->AddView(std::move(instrument_selector), std::move(meter_selector), std::move(sum_view));

    // histogram view
    std::string histogram_name = metrics_name + "_histogram";
    auto histogram_instrument_selector =
        metrics_sdk::InstrumentSelectorFactory::Create(metrics_sdk::InstrumentType::kHistogram, histogram_name, "");
    auto histogram_meter_selector =
        metrics_sdk::MeterSelectorFactory::Create(histogram_name, metrics_version, metrics_schema);
    auto histogram_view =
        metrics_sdk::ViewFactory::Create(histogram_name, "description", "", metrics_sdk::AggregationType::kHistogram);
    p->AddView(std::move(histogram_instrument_selector), std::move(histogram_meter_selector),
               std::move(histogram_view));
}

// -- collect metric stuff -----------------------------------------------------

template<typename T>
zeek::RecordValPtr Manager::GetMetricOptsRecord(Manager::MetricType metric_type,
                                                const broker::telemetry::metric_family_hdl* family) {
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
    static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");
    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");

    static auto prefix_idx = metric_opts_type->FieldOffset("prefix");
    static auto name_idx = metric_opts_type->FieldOffset("name");
    static auto help_text_idx = metric_opts_type->FieldOffset("help_text");
    static auto unit_idx = metric_opts_type->FieldOffset("unit");
    static auto is_total_idx = metric_opts_type->FieldOffset("is_total");
    static auto labels_idx = metric_opts_type->FieldOffset("labels");
    static auto bounds_idx = metric_opts_type->FieldOffset("bounds");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    if ( const auto& it = metric_opts_cache.find(family); it != metric_opts_cache.end() )
        return it->second;

    auto r = make_intrusive<zeek::RecordVal>(metric_opts_type);
    r->Assign(prefix_idx, make_intrusive<zeek::StringVal>(broker::telemetry::prefix(family)));
    r->Assign(name_idx, make_intrusive<zeek::StringVal>(broker::telemetry::name(family)));
    r->Assign(help_text_idx, make_intrusive<zeek::StringVal>(broker::telemetry::helptext(family)));
    r->Assign(unit_idx, make_intrusive<zeek::StringVal>(broker::telemetry::unit(family)));
    r->Assign(is_total_idx, val_mgr->Bool(broker::telemetry::is_sum(family)));

    auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& l : broker::telemetry::label_names(family) )
        label_names_vec->Append(make_intrusive<StringVal>(l));

    r->Assign(labels_idx, label_names_vec);

    // This is mapping Manager.h enums to bif values depending on
    // the template type and whether this is a counter, gauge or
    // histogram.
    zeek_int_t metric_type_int = -1;
    if constexpr ( std::is_same_v<T, double> ) {
        switch ( metric_type ) {
            case MetricType::Counter: metric_type_int = BifEnum::Telemetry::MetricType::DOUBLE_COUNTER; break;
            case MetricType::Gauge: metric_type_int = BifEnum::Telemetry::MetricType::DOUBLE_GAUGE; break;
            case MetricType::Histogram: metric_type_int = BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM; break;
        }
    }
    else {
        switch ( metric_type ) {
            case MetricType::Counter: metric_type_int = BifEnum::Telemetry::MetricType::INT_COUNTER; break;
            case MetricType::Gauge: metric_type_int = BifEnum::Telemetry::MetricType::INT_GAUGE; break;
            case MetricType::Histogram: metric_type_int = BifEnum::Telemetry::MetricType::INT_HISTOGRAM; break;
        }
    }

    if ( metric_type_int < 0 )
        reporter->FatalError("Unable to lookup metric type %d", int(metric_type));

    r->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(metric_type_int));

    // Add bounds and optionally count_bounds into the MetricOpts record.
    static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto opts_rt_idx_bounds = opts_rt->FieldOffset("bounds");
    static auto opts_rt_idx_count_bounds = opts_rt->FieldOffset("count_bounds");

    if ( metric_type == MetricType::Histogram ) {
        auto add_double_bounds = [](auto& r, const auto* histogram_family) {
            size_t buckets = broker::telemetry::num_buckets(histogram_family);
            auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            for ( size_t i = 0; i < buckets; i++ )
                bounds_vec->Append(as_double_val(broker::telemetry::upper_bound_at(histogram_family, i)));

            r->Assign(opts_rt_idx_bounds, bounds_vec);
        };

        if constexpr ( std::is_same_v<T, int64_t> ) {
            auto histogram_family = broker::telemetry::as_int_histogram_family(family);
            add_double_bounds(r, histogram_family);

            // Add count_bounds to int64_t histograms
            size_t buckets = broker::telemetry::num_buckets(histogram_family);
            auto count_bounds_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
            for ( size_t i = 0; i < buckets; i++ )
                count_bounds_vec->Append(val_mgr->Count(broker::telemetry::upper_bound_at(histogram_family, i)));

            r->Assign(opts_rt_idx_count_bounds, count_bounds_vec);
        }
        else {
            static_assert(std::is_same_v<T, double>);
            add_double_bounds(r, broker::telemetry::as_dbl_histogram_family(family));
        }
    }

    metric_opts_cache.insert({family, r});

    return r;
}

zeek::RecordValPtr Manager::CollectedValueMetric::AsMetricRecord() const {
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    static auto opts_idx = metric_record_type->FieldOffset("opts");
    static auto labels_idx = metric_record_type->FieldOffset("labels");
    static auto value_idx = metric_record_type->FieldOffset("value");
    static auto count_value_idx = metric_record_type->FieldOffset("count_value");

    auto r = make_intrusive<zeek::RecordVal>(metric_record_type);

    auto label_values_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& l : label_values )
        label_values_vec->Append(make_intrusive<StringVal>(l));

    r->Assign(labels_idx, label_values_vec);

    auto fn = [&](auto val) {
        using val_t = decltype(val);
        auto opts_record = telemetry_mgr->GetMetricOptsRecord<val_t>(metric_type, family);
        r->Assign(opts_idx, opts_record);
        r->Assign(value_idx, as_double_val(val));
        if constexpr ( std::is_same_v<val_t, int64_t> )
            r->Assign(count_value_idx, val_mgr->Count(val));
    };

    std::visit(fn, value);

    return r;
}

zeek::RecordValPtr Manager::CollectedHistogramMetric::AsHistogramMetricRecord() const {
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

    auto r = make_intrusive<zeek::RecordVal>(histogram_metric_type);

    auto label_values_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& l : label_values )
        label_values_vec->Append(make_intrusive<StringVal>(l));

    r->Assign(labels_idx, label_values_vec);

    auto fn = [&](const auto& histogram_data) {
        using val_t = std::decay_t<decltype(histogram_data.sum)>;
        auto opts_record = telemetry_mgr->GetMetricOptsRecord<val_t>(MetricType::Histogram, family);
        r->Assign(opts_idx, opts_record);

        val_t observations = 0;
        auto values_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
        auto count_values_vec = make_intrusive<zeek::VectorVal>(count_vec_type);

        for ( const auto& b : histogram_data.buckets ) {
            observations += b.count;
            values_vec->Append(as_double_val(b.count));
            if constexpr ( std::is_same_v<val_t, int64_t> )
                count_values_vec->Append(val_mgr->Count(b.count));
        }

        r->Assign(values_idx, values_vec);
        r->Assign(sum_idx, as_double_val(histogram_data.sum));
        r->Assign(observations_idx, as_double_val(observations));

        // Add extra fields just for int64_t based histograms with type count
        if constexpr ( std::is_same_v<val_t, int64_t> ) {
            r->Assign(count_values_idx, count_values_vec);
            r->Assign(count_sum_idx, val_mgr->Count(histogram_data.sum));
            r->Assign(count_observations_idx, val_mgr->Count(observations));
        }
    };

    std::visit(fn, histogram);

    return r;
}

/**
 * Encapsulate matching of prefix and name against a broker::telemetry::metric_family_hdl
 */
class MetricFamilyMatcher {
public:
    MetricFamilyMatcher(std::string_view prefix, std::string_view name) : prefix_pattern(prefix), name_pattern(name) {}

    /**
     * @return true if the given family's prefix and name match, else false;
     */
    bool operator()(const broker::telemetry::metric_family_hdl* family) {
        auto prefix = std::string{broker::telemetry::prefix(family)};
        auto name = std::string{broker::telemetry::name(family)};

        return fnmatch(prefix_pattern.c_str(), prefix.c_str(), 0) != FNM_NOMATCH &&
               fnmatch(name_pattern.c_str(), name.c_str(), 0) != FNM_NOMATCH;
    }

private:
    std::string prefix_pattern;
    std::string name_pattern;
};

/**
 * A collector implementation for counters and gauges.
 */
class MetricsCollector : public broker::telemetry::metrics_collector {
    using MetricType = Manager::MetricType;

public:
    MetricsCollector(std::string_view prefix, std::string_view name) : matches(prefix, name) {}

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::dbl_counter_hdl* counter,
                    broker::telemetry::const_label_list labels) override {
        if ( matches(family) )
            metrics.emplace_back(MetricType::Counter, family, extract_label_values(labels),
                                 broker::telemetry::value(counter));
    }

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::int_counter_hdl* counter,
                    broker::telemetry::const_label_list labels) override {
        if ( matches(family) )
            metrics.emplace_back(MetricType::Counter, family, extract_label_values(labels),
                                 broker::telemetry::value(counter));
    }

    void operator()(const broker::telemetry::metric_family_hdl* family, const broker::telemetry::dbl_gauge_hdl* gauge,
                    broker::telemetry::const_label_list labels) override {
        if ( matches(family) )
            metrics.emplace_back(MetricType::Gauge, family, extract_label_values(labels),
                                 broker::telemetry::value(gauge));
    }

    void operator()(const broker::telemetry::metric_family_hdl* family, const broker::telemetry::int_gauge_hdl* gauge,
                    broker::telemetry::const_label_list labels) override {
        if ( matches(family) )
            metrics.emplace_back(MetricType::Gauge, family, extract_label_values(labels),
                                 broker::telemetry::value(gauge));
    }

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::dbl_histogram_hdl* histogram,
                    broker::telemetry::const_label_list labels) override {
        // Ignored
    }

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::int_histogram_hdl* histogram,
                    broker::telemetry::const_label_list labels) override {
        // Ignored
    }

    std::vector<Manager::CollectedValueMetric>& GetResult() { return metrics; }

private:
    MetricFamilyMatcher matches;
    std::vector<Manager::CollectedValueMetric> metrics;
};

std::vector<Manager::CollectedValueMetric> Manager::CollectMetrics(std::string_view prefix, std::string_view name) {
    auto collector = MetricsCollector(prefix, name);

    pimpl->collect(collector);

    return std::move(collector.GetResult());
}

/**
 * A collector implementation for histograms.
 */
class HistogramMetricsCollector : public broker::telemetry::metrics_collector {
    using MetricType = Manager::MetricType;

public:
    HistogramMetricsCollector(std::string_view prefix, std::string_view name) : matches(prefix, name) {}

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::dbl_counter_hdl* counter,
                    broker::telemetry::const_label_list labels) override {
        // Ignored
    }

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::int_counter_hdl* counter,
                    broker::telemetry::const_label_list labels) override {
        // Ignored
    }

    void operator()(const broker::telemetry::metric_family_hdl* family, const broker::telemetry::dbl_gauge_hdl* gauge,
                    broker::telemetry::const_label_list labels) override {
        // Ignored
    }

    void operator()(const broker::telemetry::metric_family_hdl* family, const broker::telemetry::int_gauge_hdl* gauge,
                    broker::telemetry::const_label_list labels) override {
        // Ignored
    }

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::dbl_histogram_hdl* histogram,
                    broker::telemetry::const_label_list labels) override {
        if ( ! matches(family) )
            return;

        size_t num_buckets = broker::telemetry::num_buckets(histogram);

        Manager::CollectedHistogramMetric::DblHistogramData histogram_data;
        histogram_data.buckets.reserve(num_buckets);

        for ( size_t i = 0; i < num_buckets; i++ ) {
            double c = broker::telemetry::count_at(histogram, i);
            double ub = broker::telemetry::upper_bound_at(histogram, i);
            histogram_data.buckets.emplace_back(c, ub);
        }

        histogram_data.sum = broker::telemetry::sum(histogram);

        metrics.emplace_back(family, extract_label_values(labels), std::move(histogram_data));
    }

    void operator()(const broker::telemetry::metric_family_hdl* family,
                    const broker::telemetry::int_histogram_hdl* histogram,
                    broker::telemetry::const_label_list labels) override {
        if ( ! matches(family) )
            return;

        size_t num_buckets = broker::telemetry::num_buckets(histogram);

        Manager::CollectedHistogramMetric::IntHistogramData histogram_data;
        histogram_data.buckets.reserve(num_buckets);

        for ( size_t i = 0; i < num_buckets; i++ ) {
            int64_t c = broker::telemetry::count_at(histogram, i);
            int64_t ub = broker::telemetry::upper_bound_at(histogram, i);
            histogram_data.buckets.emplace_back(c, ub);
        }

        histogram_data.sum = broker::telemetry::sum(histogram);

        metrics.emplace_back(family, extract_label_values(labels), std::move(histogram_data));
    }

    std::vector<Manager::CollectedHistogramMetric>& GetResult() { return metrics; }

private:
    MetricFamilyMatcher matches;
    std::vector<Manager::CollectedHistogramMetric> metrics;
};

std::vector<Manager::CollectedHistogramMetric> Manager::CollectHistogramMetrics(std::string_view prefix,
                                                                                std::string_view name) {
    auto collector = HistogramMetricsCollector(prefix, name);

    pimpl->collect(collector);

    return std::move(collector.GetResult());
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
                CHECK_EQ(family.Prefix(), "zeek"sv);
                CHECK_EQ(family.Name(), "requests"sv);
                CHECK_EQ(toVector(family.LabelNames()), std::vector{"method"s});
                CHECK_EQ(family.Helptext(), "test"sv);
                CHECK_EQ(family.Unit(), "1"sv);
                CHECK_EQ(family.IsSum(), true);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family.GetOrAdd({{"method", "get"}});
                auto second = family.GetOrAdd({{"method", "get"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family.GetOrAdd({{"method", "get"}});
                auto second = family.GetOrAdd({{"method", "put"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblCounter family") {
            auto family = mgr.CounterFamily<double>("zeek", "runtime", {"query"}, "test", "seconds", true);
            THEN("the family object stores the parameters") {
                CHECK_EQ(family.Prefix(), "zeek"sv);
                CHECK_EQ(family.Name(), "runtime"sv);
                CHECK_EQ(toVector(family.LabelNames()), std::vector{"query"s});
                CHECK_EQ(family.Helptext(), "test"sv);
                CHECK_EQ(family.Unit(), "seconds"sv);
                CHECK_EQ(family.IsSum(), true);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family.GetOrAdd({{"query", "foo"}});
                auto second = family.GetOrAdd({{"query", "foo"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family.GetOrAdd({{"query", "foo"}});
                auto second = family.GetOrAdd({{"query", "bar"}});
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
                CHECK_EQ(family.Prefix(), "zeek"sv);
                CHECK_EQ(family.Name(), "open-connections"sv);
                CHECK_EQ(toVector(family.LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family.Helptext(), "test"sv);
                CHECK_EQ(family.Unit(), "1"sv);
                CHECK_EQ(family.IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family.GetOrAdd({{"protocol", "tcp"}});
                auto second = family.GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family.GetOrAdd({{"protocol", "tcp"}});
                auto second = family.GetOrAdd({{"protocol", "quic"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblGauge family") {
            auto family = mgr.GaugeFamily<double>("zeek", "water-level", {"river"}, "test", "meters");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family.Prefix(), "zeek"sv);
                CHECK_EQ(family.Name(), "water-level"sv);
                CHECK_EQ(toVector(family.LabelNames()), std::vector{"river"s});
                CHECK_EQ(family.Helptext(), "test"sv);
                CHECK_EQ(family.Unit(), "meters"sv);
                CHECK_EQ(family.IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family.GetOrAdd({{"river", "Sacramento"}});
                auto second = family.GetOrAdd({{"river", "Sacramento"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family.GetOrAdd({{"query", "Sacramento"}});
                auto second = family.GetOrAdd({{"query", "San Joaquin"}});
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
                CHECK_EQ(family.Prefix(), "zeek"sv);
                CHECK_EQ(family.Name(), "payload-size"sv);
                CHECK_EQ(toVector(family.LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family.Helptext(), "test"sv);
                CHECK_EQ(family.Unit(), "bytes"sv);
                CHECK_EQ(family.IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family.GetOrAdd({{"protocol", "tcp"}});
                auto second = family.GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family.GetOrAdd({{"protocol", "tcp"}});
                auto second = family.GetOrAdd({{"protocol", "udp"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblHistogram family") {
            double buckets[] = {10.0, 20.0};
            auto family = mgr.HistogramFamily<double>("zeek", "parse-time", {"protocol"}, buckets, "test", "seconds");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family.Prefix(), "zeek"sv);
                CHECK_EQ(family.Name(), "parse-time"sv);
                CHECK_EQ(toVector(family.LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family.Helptext(), "test"sv);
                CHECK_EQ(family.Unit(), "seconds"sv);
                CHECK_EQ(family.IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family.GetOrAdd({{"protocol", "tcp"}});
                auto second = family.GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family.GetOrAdd({{"protocol", "tcp"}});
                auto second = family.GetOrAdd({{"protocol", "udp"}});
                CHECK_NE(first, second);
            }
            AND_THEN("Timers add observations to histograms") {
                auto hg = family.GetOrAdd({{"protocol", "tst"}});
                CHECK_EQ(hg.Sum(), 0.0);
                {
                    Timer observer{hg};
                    std::this_thread::sleep_for(1ms);
                }
                CHECK_NE(hg.Sum(), 0.0);
            }
        }
    }
}
