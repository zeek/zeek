// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define RAPIDJSON_HAS_STDSTRING 1

// CivetServer is from the civetweb submodule in prometheus-cpp
#include <CivetServer.h>
#include <fnmatch.h>
#include <prometheus/collectable.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <algorithm>
#include <thread>

#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/IPAddr.h"
#include "zeek/RunState.h"
#include "zeek/ZeekString.h"
#include "zeek/iosource/Manager.h"
#include "zeek/telemetry/ProcessStats.h"
#include "zeek/telemetry/Timer.h"
#include "zeek/threading/formatters/detail/json.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek::telemetry {

/**
 * Prometheus Collectable interface used to insert Zeek callback processing
 * before the Prometheus registry's collection of metric data.
 */
class ZeekCollectable : public prometheus::Collectable {
public:
    std::vector<prometheus::MetricFamily> Collect() const override {
        telemetry_mgr->WaitForPrometheusCallbacks();
        return {};
    }
};

Manager::Manager() : IOSource(true) { prometheus_registry = std::make_shared<prometheus::Registry>(); }

Manager::~Manager() {}

void Manager::InitPostScript() {
    // Metrics port setting is used to calculate a URL for prometheus scraping
    std::string prometheus_url;
    auto metrics_port = id::find_val("Telemetry::metrics_port")->AsPortVal();
    auto metrics_address = id::find_val("Telemetry::metrics_address")->AsStringVal()->ToStdString();
    if ( metrics_address.empty() )
        metrics_address = "0.0.0.0";
    if ( metrics_port->Port() != 0 )
        prometheus_url = util::fmt("%s:%u", metrics_address.data(), metrics_port->Port());

    if ( ! prometheus_url.empty() && ! getenv("ZEEKCTL_CHECK_CONFIG") ) {
        CivetCallbacks* callbacks = nullptr;
        auto local_node_name = id::find_val("Cluster::node")->AsStringVal();
        if ( local_node_name->Len() > 0 ) {
            auto cluster_nodes = id::find_val("Cluster::nodes")->AsTableVal();
            auto local_node = cluster_nodes->Find(IntrusivePtr<StringVal>{NewRef{}, local_node_name});
            auto local_node_type = local_node->AsRecordVal()->GetField<EnumVal>("node_type")->Get();

            static auto node_type_type = id::find_type("Cluster::NodeType")->AsEnumType();
            static auto manager_type = node_type_type->Lookup("Cluster", "MANAGER");

            if ( local_node_type == manager_type ) {
                BuildClusterJson();

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
            prometheus_exposer =
                std::make_unique<prometheus::Exposer>(prometheus_url, BifConst::Telemetry::civetweb_threads, callbacks);

            // CivetWeb stores a copy of the callbacks, so we're safe to delete the pointer here
            delete callbacks;
        } catch ( const CivetException& exc ) {
            reporter->FatalError("Failed to setup Prometheus endpoint: %s. Attempted to bind to %s.", exc.what(),
                                 prometheus_url.c_str());
        }

        // This has to be inserted before the registry below. The exposer
        // processes the collectors in order of insertion. We want to make
        // sure that the callbacks get called and the values in the metrics
        // are updated before prometheus-cpp scrapes them.
        zeek_collectable = std::make_shared<ZeekCollectable>();
        prometheus_exposer->RegisterCollectable(zeek_collectable);

        prometheus_exposer->RegisterCollectable(prometheus_registry);
    }

#ifdef HAVE_PROCESS_STAT_METRICS
    static auto get_stats = []() -> const detail::process_stats* {
        double now = util::current_time();
        if ( telemetry_mgr->process_stats_last_updated < now - 0.01 ) {
            telemetry_mgr->current_process_stats = detail::get_process_stats();
            telemetry_mgr->process_stats_last_updated = now;
        }

        return &telemetry_mgr->current_process_stats;
    };
    rss_gauge = GaugeInstance("process", "resident_memory", {}, "Resident memory size", "bytes",
                              []() { return static_cast<double>(get_stats()->rss); });

    vms_gauge = GaugeInstance("process", "virtual_memory", {}, "Virtual memory size", "bytes",
                              []() { return static_cast<double>(get_stats()->vms); });

    cpu_user_counter = CounterInstance("process", "cpu_user", {}, "Total user CPU time spent", "seconds",
                                       []() { return get_stats()->cpu_user; });

    cpu_system_counter = CounterInstance("process", "cpu_system", {}, "Total system CPU time spent", "seconds",
                                         []() { return get_stats()->cpu_system; });

    fds_gauge = GaugeInstance("process", "open_fds", {}, "Number of open file descriptors", "",
                              []() { return static_cast<double>(get_stats()->fds); });
#endif

    if ( ! iosource_mgr->RegisterFd(collector_flare.FD(), this) ) {
        reporter->FatalError("Failed to register telemetry collector descriptor");
    }
}

void Manager::Terminate() {
    // Notify the collector condition so that it doesn't hang waiting for
    // a collector request to complete.
    collector_cv.notify_all();

    // Shut down the exposer first of all so we stop getting requests for
    // data. This keeps us from getting a request on another thread while
    // we're shutting down.
    prometheus_exposer.reset();

    iosource_mgr->UnregisterFd(collector_flare.FD(), this);
}

// -- collect metric stuff -----------------------------------------------------

RecordValPtr Manager::GetMetricOptsRecord(const prometheus::MetricFamily& metric_family) {
    // Avoid recreating this repeatedly.
    // TODO: this may cause problems if new metrics are added or removed by external users,
    // since the validation of label names needs to happen.
    if ( auto it = opts_records.find(metric_family.name); it != opts_records.end() )
        return it->second;

    // Get the opt record
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");

    static auto prefix_idx = metric_opts_type->FieldOffset("prefix");
    static auto name_idx = metric_opts_type->FieldOffset("name");
    static auto help_text_idx = metric_opts_type->FieldOffset("help_text");
    static auto unit_idx = metric_opts_type->FieldOffset("unit");
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
    record_val->Assign(is_total_idx, val_mgr->Bool(metric_family.name.ends_with("_total")));

    if ( metric_family.type == prometheus::MetricType::Counter )
        record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                BifEnum::Telemetry::MetricType::COUNTER));
    if ( metric_family.type == prometheus::MetricType::Gauge )
        record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                BifEnum::Telemetry::MetricType::GAUGE));
    if ( metric_family.type == prometheus::MetricType::Histogram )
        record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                BifEnum::Telemetry::MetricType::HISTOGRAM));

    opts_records.insert({metric_family.name, record_val});

    return record_val;
}

static bool comparer(const std::optional<ZVal>& a, const std::optional<ZVal>& b, const RecordTypePtr& type) {
    if ( ! a )
        return false;

    if ( ! b )
        return true;

    auto a_r = a->ToVal(type)->AsRecordVal();
    auto b_r = b->ToVal(type)->AsRecordVal();

    auto a_opts = a_r->GetField<RecordVal>("opts");
    auto b_opts = b_r->GetField<RecordVal>("opts");

    auto a_name = a_opts->GetField<StringVal>("name");
    auto b_name = b_opts->GetField<StringVal>("name");
    if ( a_name->Len() > b_name->Len() )
        return false;
    if ( a_name->Len() < b_name->Len() )
        return true;
    if ( memcmp(a_name->Bytes(), b_name->Bytes(), a_name->Len()) < 0 )
        return true;

    auto a_prefix = a_opts->GetField<StringVal>("prefix");
    auto b_prefix = b_opts->GetField<StringVal>("prefix");
    if ( a_prefix->Len() > b_prefix->Len() )
        return false;
    if ( a_prefix->Len() < b_prefix->Len() )
        return true;
    if ( memcmp(a_prefix->Bytes(), b_prefix->Bytes(), a_prefix->Len()) < 0 )
        return true;

    auto a_labels = a_r->GetField<VectorVal>("label_values");
    std::vector<std::string> a_label_vec;
    a_label_vec.reserve(a_labels->Size());
    for ( const auto& sv : a_labels->RawVec() )
        a_label_vec.push_back(sv->AsString()->ToStdString());

    auto b_labels = b_r->GetField<VectorVal>("label_values");
    std::vector<std::string> b_label_vec;
    b_label_vec.reserve(b_labels->Size());
    for ( const auto& sv : b_labels->RawVec() )
        b_label_vec.push_back(sv->AsString()->ToStdString());

    return a_label_vec < b_label_vec;
}

static bool compare_metrics(const std::optional<ZVal>& a, const std::optional<ZVal>& b) {
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    return comparer(a, b, metric_record_type);
}

static bool compare_histograms(const std::optional<ZVal>& a, const std::optional<ZVal>& b) {
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
    return comparer(a, b, metric_record_type);
}

void Manager::InvokeTelemetrySyncHook() {
    static const auto sync_hook = zeek::id::find_func("Telemetry::sync");

    if ( sync_hook->Flavor() != FUNC_FLAVOR_HOOK )
        reporter->InternalError("Telemetry::sync not a hook?");

    if ( in_sync_hook ) {
        reporter->Warning("Telemetry::sync() hook invoked recursively");
        return;
    }

    in_sync_hook = true;

    zeek::Args empty;
    auto result = sync_hook->Invoke(&empty);

    if ( ! result->IsOne() )
        reporter->Warning("Telemetry::sync() implementations skipped due to 'break' usage");

    in_sync_hook = false;
}


void Manager::UpdateMetrics() {
    InvokeTelemetrySyncHook();

    for ( const auto& [name, f] : families )
        f->RunCallbacks();
}

ValPtr Manager::CollectMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("Telemetry::MetricVector");
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    static auto opts_idx = metric_record_type->FieldOffset("opts");
    static auto value_idx = metric_record_type->FieldOffset("value");
    static auto label_names_idx = metric_record_type->FieldOffset("label_names");
    static auto label_values_idx = metric_record_type->FieldOffset("label_values");

    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    UpdateMetrics();

    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Due to the name containing the full information about a metric including a potential unit add an
    // asterisk to the end of the full pattern so matches work correctly.
    std::string full_pattern = util::fmt("%.*s_%.*s", static_cast<int>(prefix_pattern.size()), prefix_pattern.data(),
                                         static_cast<int>(name_pattern.size()), name_pattern.data());
    if ( full_pattern[full_pattern.size() - 1] != '*' )
        full_pattern.append("*");

    auto collected = prometheus_registry->Collect();
    ret_val->Reserve(collected.size());

    for ( const auto& fam : collected ) {
        if ( fam.type == prometheus::MetricType::Histogram )
            continue;

        if ( fnmatch(full_pattern.c_str(), fam.name.c_str(), 0) == FNM_NOMATCH )
            continue;

        RecordValPtr opts_record = GetMetricOptsRecord(fam);

        for ( const auto& inst : fam.metric ) {
            auto r = make_intrusive<zeek::RecordVal>(metric_record_type);
            r->Assign(opts_idx, opts_record);

            if ( fam.type == prometheus::MetricType::Counter )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(inst.counter.value));
            else if ( fam.type == prometheus::MetricType::Gauge )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(inst.gauge.value));

            auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
            auto label_values_vec = make_intrusive<zeek::VectorVal>(string_vec_type);

            for ( const auto& lbl : inst.label ) {
                label_names_vec->Append(make_intrusive<StringVal>(lbl.name));
                label_values_vec->Append(make_intrusive<StringVal>(lbl.value));
            }

            r->Assign(label_names_idx, std::move(label_names_vec));
            r->Assign(label_values_idx, std::move(label_values_vec));

            ret_val->Append(std::move(r));
        }
    }

    // If running under test, there are issues with the non-deterministic
    // ordering of the metrics coming out of prometheus-cpp, which uses
    // std::hash on the label values to sort them. Check for that case and sort
    // the results to some fixed order so that the tests have consistent
    // results.
    if ( ret_val->Size() > 0 ) {
        static auto running_under_test = id::find_val("running_under_test")->AsBool();
        if ( running_under_test ) {
            auto& vec = ret_val->RawVec();
            std::sort(vec.begin(), vec.end(), compare_metrics);
        }
    }

    return std::move(ret_val);
}

ValPtr Manager::CollectHistogramMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("Telemetry::HistogramMetricVector");
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
    static auto histogram_metric_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
    static auto values_idx = histogram_metric_type->FieldOffset("values");
    static auto label_names_idx = histogram_metric_type->FieldOffset("label_names");
    static auto label_values_idx = histogram_metric_type->FieldOffset("label_values");

    static auto observations_idx = histogram_metric_type->FieldOffset("observations");
    static auto sum_idx = histogram_metric_type->FieldOffset("sum");

    static auto opts_idx = histogram_metric_type->FieldOffset("opts");
    static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto bounds_idx = opts_rt->FieldOffset("bounds");

    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    UpdateMetrics();

    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Due to the name containing the full information about a metric including a potential unit add an
    // asterisk to the end of the full pattern so matches work correctly.
    std::string full_pattern = util::fmt("%.*s_%.*s", static_cast<int>(prefix_pattern.size()), prefix_pattern.data(),
                                         static_cast<int>(name_pattern.size()), name_pattern.data());
    if ( full_pattern[full_pattern.size() - 1] != '*' )
        full_pattern.append("*");

    auto collected = prometheus_registry->Collect();
    ret_val->Reserve(collected.size());

    for ( const auto& fam : collected ) {
        if ( fam.type != prometheus::MetricType::Histogram )
            continue;

        if ( fnmatch(full_pattern.c_str(), fam.name.c_str(), 0) == FNM_NOMATCH )
            continue;

        RecordValPtr opts_record = GetMetricOptsRecord(fam);

        for ( const auto& inst : fam.metric ) {
            auto r = make_intrusive<zeek::RecordVal>(histogram_metric_type);
            r->Assign(opts_idx, opts_record);

            auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
            auto label_values_vec = make_intrusive<zeek::VectorVal>(string_vec_type);

            for ( const auto& lbl : inst.label ) {
                label_names_vec->Append(make_intrusive<StringVal>(lbl.name));
                label_values_vec->Append(make_intrusive<StringVal>(lbl.value));
            }

            r->Assign(label_names_idx, std::move(label_names_vec));
            r->Assign(label_values_idx, std::move(label_values_vec));

            auto double_values_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            std::vector<double> boundaries;
            uint64_t last = 0.0;
            for ( const auto& b : inst.histogram.bucket ) {
                double_values_vec->Append(
                    zeek::make_intrusive<DoubleVal>(static_cast<double>(b.cumulative_count - last)));
                last = b.cumulative_count;
                boundaries.push_back(b.upper_bound);
            }

            // TODO: these could be stored somehow to avoid recreating them repeatedly
            auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            for ( auto b : boundaries )
                bounds_vec->Append(zeek::make_intrusive<DoubleVal>(b));

            r->Assign(values_idx, double_values_vec);
            r->Assign(observations_idx,
                      zeek::make_intrusive<DoubleVal>(static_cast<double>(inst.histogram.sample_count)));
            r->Assign(sum_idx, zeek::make_intrusive<DoubleVal>(inst.histogram.sample_sum));

            RecordValPtr local_opts_record = r->GetField<RecordVal>(opts_idx);
            local_opts_record->Assign(bounds_idx, std::move(bounds_vec));

            ret_val->Append(std::move(r));
        }
    }

    // If running under btest, there are issues with the non-deterministic
    // ordering of the metrics coming out of prometheus-cpp, which uses
    // std::hash on the label values to sort them. Check for that case and sort
    // the results to some fixed order so that the tests have consistent
    // results.
    if ( ret_val->Size() > 0 ) {
        static auto running_under_test = id::find_val("running_under_test")->AsBool();
        if ( running_under_test ) {
            auto& vec = ret_val->RawVec();
            std::sort(vec.begin(), vec.end(), compare_histograms);
        }
    }

    return std::move(ret_val);
}

void Manager::BuildClusterJson() {
    rapidjson::StringBuffer buffer;
    json::detail::NullDoubleWriter writer(buffer);

    writer.StartArray();
    writer.StartObject();

    writer.Key("targets");
    writer.StartArray();
    auto& node_val = id::find_val("Cluster::nodes");
    auto node_map = node_val->AsTableVal()->ToMap();
    for ( const auto& [idx, value] : node_map ) {
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

    cluster_json = buffer.GetString();
}

CounterFamilyPtr Manager::CounterFamily(std::string_view prefix, std::string_view name,
                                        Span<const std::string_view> labels, std::string_view helptext,
                                        std::string_view unit) {
    auto full_name = detail::BuildFullPrometheusName(prefix, name, unit, true);

    auto& prom_fam =
        prometheus::BuildCounter().Name(full_name).Help(std::string{helptext}).Register(*prometheus_registry);

    if ( auto it = families.find(prom_fam.GetName()); it != families.end() )
        return std::static_pointer_cast<telemetry::CounterFamily>(it->second);

    auto fam = std::make_shared<telemetry::CounterFamily>(&prom_fam, labels);
    families.insert({prom_fam.GetName(), fam});
    return fam;
}

CounterFamilyPtr Manager::CounterFamily(std::string_view prefix, std::string_view name,
                                        std::initializer_list<std::string_view> labels, std::string_view helptext,
                                        std::string_view unit) {
    auto lbl_span = Span{labels.begin(), labels.size()};
    return CounterFamily(prefix, name, lbl_span, helptext, unit);
}

CounterPtr Manager::CounterInstance(std::string_view prefix, std::string_view name, Span<const LabelView> labels,
                                    std::string_view helptext, std::string_view unit,
                                    detail::CollectCallbackPtr callback) {
    return WithLabelNames(labels, [&, this](auto labelNames) {
        auto family = CounterFamily(prefix, name, labelNames, helptext, unit);
        return family->GetOrAdd(labels, callback);
    });
}

CounterPtr Manager::CounterInstance(std::string_view prefix, std::string_view name,
                                    std::initializer_list<LabelView> labels, std::string_view helptext,
                                    std::string_view unit, detail::CollectCallbackPtr callback) {
    auto lbl_span = Span{labels.begin(), labels.size()};
    return CounterInstance(prefix, name, lbl_span, helptext, unit, std::move(callback));
}

std::shared_ptr<GaugeFamily> Manager::GaugeFamily(std::string_view prefix, std::string_view name,
                                                  Span<const std::string_view> labels, std::string_view helptext,
                                                  std::string_view unit) {
    auto full_name = detail::BuildFullPrometheusName(prefix, name, unit, false);

    auto& prom_fam =
        prometheus::BuildGauge().Name(full_name).Help(std::string{helptext}).Register(*prometheus_registry);

    if ( auto it = families.find(prom_fam.GetName()); it != families.end() )
        return std::static_pointer_cast<telemetry::GaugeFamily>(it->second);

    auto fam = std::make_shared<telemetry::GaugeFamily>(&prom_fam, labels);
    families.insert({prom_fam.GetName(), fam});
    return fam;
}

GaugeFamilyPtr Manager::GaugeFamily(std::string_view prefix, std::string_view name,
                                    std::initializer_list<std::string_view> labels, std::string_view helptext,
                                    std::string_view unit) {
    auto lbl_span = Span{labels.begin(), labels.size()};
    return GaugeFamily(prefix, name, lbl_span, helptext, unit);
}

GaugePtr Manager::GaugeInstance(std::string_view prefix, std::string_view name, Span<const LabelView> labels,
                                std::string_view helptext, std::string_view unit, detail::CollectCallbackPtr callback) {
    return WithLabelNames(labels, [&, this](auto labelNames) {
        auto family = GaugeFamily(prefix, name, labelNames, helptext, unit);
        return family->GetOrAdd(labels, callback);
    });
}

GaugePtr Manager::GaugeInstance(std::string_view prefix, std::string_view name, std::initializer_list<LabelView> labels,
                                std::string_view helptext, std::string_view unit, detail::CollectCallbackPtr callback) {
    auto lbl_span = Span{labels.begin(), labels.size()};
    return GaugeInstance(prefix, name, lbl_span, helptext, unit, std::move(callback));
}

HistogramFamilyPtr Manager::HistogramFamily(std::string_view prefix, std::string_view name,
                                            Span<const std::string_view> labels, ConstSpan<double> bounds,
                                            std::string_view helptext, std::string_view unit) {
    auto full_name = detail::BuildFullPrometheusName(prefix, name, unit);

    auto& prom_fam =
        prometheus::BuildHistogram().Name(full_name).Help(std::string{helptext}).Register(*prometheus_registry);

    if ( auto it = families.find(prom_fam.GetName()); it != families.end() )
        return std::static_pointer_cast<telemetry::HistogramFamily>(it->second);

    auto fam = std::make_shared<telemetry::HistogramFamily>(&prom_fam, bounds, labels);
    families.insert({prom_fam.GetName(), fam});
    return fam;
}

HistogramFamilyPtr Manager::HistogramFamily(std::string_view prefix, std::string_view name,
                                            std::initializer_list<std::string_view> labels, ConstSpan<double> bounds,
                                            std::string_view helptext, std::string_view unit) {
    auto lbl_span = Span{labels.begin(), labels.size()};
    return HistogramFamily(prefix, name, lbl_span, bounds, helptext, unit);
}

HistogramPtr Manager::HistogramInstance(std::string_view prefix, std::string_view name, Span<const LabelView> labels,
                                        ConstSpan<double> bounds, std::string_view helptext, std::string_view unit) {
    return WithLabelNames(labels, [&, this](auto labelNames) {
        auto family = HistogramFamily(prefix, name, labelNames, bounds, helptext, unit);
        return family->GetOrAdd(labels);
    });
}

HistogramPtr Manager::HistogramInstance(std::string_view prefix, std::string_view name,
                                        std::initializer_list<LabelView> labels, std::initializer_list<double> bounds,
                                        std::string_view helptext, std::string_view unit) {
    auto lbls = Span{labels.begin(), labels.size()};
    auto bounds_span = Span{bounds.begin(), bounds.size()};
    return HistogramInstance(prefix, name, lbls, bounds_span, helptext, unit);
}

void Manager::ProcessFd(int fd, int flags) {
    std::unique_lock<std::mutex> lk(collector_cv_mtx);

    collector_flare.Extinguish();

    UpdateMetrics();

    collector_response_idx = collector_request_idx;

    lk.unlock();
    collector_cv.notify_all();
}

void Manager::WaitForPrometheusCallbacks() {
    std::unique_lock<std::mutex> lk(collector_cv_mtx);

    ++collector_request_idx;
    uint64_t expected_idx = collector_request_idx;
    collector_flare.Fire();

    // It should *not* take 5 seconds to go through all of the callbacks, but
    // set this to have a timeout anyways just to avoid a deadlock.
    bool res = collector_cv.wait_for(lk,
                                     std::chrono::microseconds(
                                         static_cast<long>(BifConst::Telemetry::callback_timeout * 1000000)),
                                     [expected_idx]() {
                                         return telemetry_mgr->collector_response_idx >= expected_idx ||
                                                zeek::run_state::terminating;
                                     });

    if ( ! res )
        fprintf(stderr, "Timeout waiting for prometheus callbacks\n");
}

} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace std::literals;
using namespace zeek::telemetry;

SCENARIO("telemetry managers provide access to counter families") {
    GIVEN("a telemetry manager") {
        Manager mgr;
        WHEN("retrieving an IntCounter family") {
            auto family = mgr.CounterFamily("zeek", "requests", {"method"}, "test");
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
            auto family = mgr.CounterFamily("zeek", "runtime", {"query"}, "test", "seconds");
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
            auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test");
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
            auto family = mgr.GaugeFamily("zeek", "water-level", {"river"}, "test", "meters");
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
            double buckets[] = {10, 20};
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
            auto family = mgr.HistogramFamily("zeek", "parse-time", {"protocol"}, buckets, "test", "seconds");
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
