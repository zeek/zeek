// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <condition_variable>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "zeek/Flare.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"
#include "zeek/telemetry/Histogram.h"
#include "zeek/telemetry/ProcessStats.h"
#include "zeek/telemetry/Utils.h"

namespace zeek {
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
} // namespace zeek

namespace prometheus {
class Exposer;
class Registry;
} // namespace prometheus

namespace zeek::telemetry {

namespace detail {
using CollectCallbackPtr = std::function<double()>;
}

class ZeekCollectable;

/**
 * Manages a collection of metric families.
 */
class Manager final : public iosource::IOSource {
public:
    Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    ~Manager() override; // = default;

    /**
     * Initialization of the manager. This is called late during Zeek's
     * initialization after any scripts are processed. Sets up the Prometheus
     * server and the process stats metrics, and on a manager node will enable
     * the Prometheus service discovery endpoint.
     */
    void InitPostScript();

    void Terminate();

    /**
     * @return A VectorVal containing all counter and gauge metrics and their values matching prefix and name.
     * @param prefix The prefix pattern to use for filtering. Supports globbing.
     * @param name The name pattern to use for filtering. Supports globbing.
     */
    ValPtr CollectMetrics(std::string_view prefix, std::string_view name);

    /**
     * @return A VectorVal containing all histogram metrics and their values matching prefix and name.
     * @param prefix The prefix pattern to use for filtering. Supports globbing.
     * @param name The name pattern to use for filtering. Supports globbing.
     */
    ValPtr CollectHistogramMetrics(std::string_view prefix, std::string_view name);

    /**
     * @return A counter metric family. Creates the family lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Names for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     */
    CounterFamilyPtr CounterFamily(std::string_view prefix, std::string_view name,
                                   std::span<const std::string_view> labels, std::string_view helptext,
                                   std::string_view unit = "");

    /// @copydoc CounterFamily
    CounterFamilyPtr CounterFamily(std::string_view prefix, std::string_view name,
                                   std::initializer_list<std::string_view> labels, std::string_view helptext,
                                   std::string_view unit = "");

    /**
     * Accesses a counter instance. Creates the hosting metric family as well
     * as the counter lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Values for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     * @param callback Passing a callback method will enable asynchronous mode. The callback method will be called
     * by the metrics subsystem whenever data is requested.
     */
    CounterPtr CounterInstance(std::string_view prefix, std::string_view name, std::span<const LabelView> labels,
                               std::string_view helptext, std::string_view unit = "",
                               detail::CollectCallbackPtr callback = nullptr);

    /// @copydoc counterInstance
    CounterPtr CounterInstance(std::string_view prefix, std::string_view name, std::initializer_list<LabelView> labels,
                               std::string_view helptext, std::string_view unit = "",
                               detail::CollectCallbackPtr callback = nullptr);

    /**
     * @return A gauge metric family. Creates the family lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Names for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     */
    GaugeFamilyPtr GaugeFamily(std::string_view prefix, std::string_view name, std::span<const std::string_view> labels,
                               std::string_view helptext, std::string_view unit = "");

    /// @copydoc GaugeFamily
    GaugeFamilyPtr GaugeFamily(std::string_view prefix, std::string_view name,
                               std::initializer_list<std::string_view> labels, std::string_view helptext,
                               std::string_view unit = "");

    /**
     * Accesses a gauge instance. Creates the hosting metric family as well
     * as the gauge lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Values for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     * @param callback Passing a callback method will enable asynchronous mode. The callback method will be called
     * by the metrics subsystem whenever data is requested.
     */
    GaugePtr GaugeInstance(std::string_view prefix, std::string_view name, std::span<const LabelView> labels,
                           std::string_view helptext, std::string_view unit = "",
                           detail::CollectCallbackPtr callback = nullptr);

    /// @copydoc GaugeInstance
    GaugePtr GaugeInstance(std::string_view prefix, std::string_view name, std::initializer_list<LabelView> labels,
                           std::string_view helptext, std::string_view unit = "",
                           detail::CollectCallbackPtr callback = nullptr);

    /**
     * Returns a histogram metric family. Creates the family lazily if
     * necessary.
     * @param prefix The prefix (namespace) this family belongs to. Usually the
     *               application or protocol name, e.g., `http`. The prefix `caf`
     *               as well as prefixes starting with an underscore are
     *               reserved.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Names for all label dimensions of the metric.
     * @param bounds Upper bounds for the metric buckets.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement. Please use base units such as `bytes` or
     *             `seconds` (prefer lowercase). The pseudo-unit `1` identifies
     *             dimensionless counts.
     * @note The first call wins when calling this function multiple times with
     *       different bucket settings. Users may also override
     *       @p bounds via run-time configuration.
     */
    HistogramFamilyPtr HistogramFamily(std::string_view prefix, std::string_view name,
                                       std::span<const std::string_view> labels, std::span<const double> bounds,
                                       std::string_view helptext, std::string_view unit = "");

    /// @copydoc HistogramFamily
    HistogramFamilyPtr HistogramFamily(std::string_view prefix, std::string_view name,
                                       std::initializer_list<std::string_view> labels, std::span<const double> bounds,
                                       std::string_view helptext, std::string_view unit = "");

    /**
     * Returns a histogram. Creates the family lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to. Usually the
     *               application or protocol name, e.g., `http`. The prefix `caf`
     *               as well as prefixes starting with an underscore are
     *               reserved.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Names for all label dimensions of the metric.
     * @param bounds Upper bounds for the metric buckets.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement. Please use base units such as `bytes` or
     *             `seconds` (prefer lowercase). The pseudo-unit `1` identifies
     *             dimensionless counts.
     * @note The first call wins when calling this function multiple times with
     *       different bucket settings. Users may also override
     *       @p bounds via run-time configuration.
     */
    HistogramPtr HistogramInstance(std::string_view prefix, std::string_view name, std::span<const LabelView> labels,
                                   std::span<const double> bounds, std::string_view helptext,
                                   std::string_view unit = "");

    /// @copdoc HistogramInstance
    HistogramPtr HistogramInstance(std::string_view prefix, std::string_view name,
                                   std::initializer_list<LabelView> labels, std::initializer_list<double> bounds,
                                   std::string_view helptext, std::string_view unit = "");

    /**
     * @return A JSON description of the cluster configuration for reporting
     * to Prometheus for service discovery requests.
     */
    std::string GetClusterJson() const { return cluster_json; }

    /**
     * @return The pointer to the prometheus-cpp registry used by the telemetry
     * manager. This is public so that third parties (such as broker) can add
     * elements to it directly.
     */
    std::shared_ptr<prometheus::Registry> GetRegistry() const { return prometheus_registry; }

    // IOSource interface
    double GetNextTimeout() override { return -1.0; }
    void Process() override {}
    const char* Tag() override { return "Telemetry::Manager"; }
    void ProcessFd(int fd, int flags) override;

protected:
    template<class F>
    static auto WithLabelNames(std::span<const LabelView> xs, F continuation) {
        if ( xs.size() <= 10 ) {
            std::string_view buf[10];
            for ( size_t index = 0; index < xs.size(); ++index )
                buf[index] = xs[index].first;

            return continuation(std::span{buf, xs.size()});
        }
        else {
            std::vector<std::string_view> buf;
            for ( auto x : xs )
                buf.emplace_back(x.first);

            return continuation(std::span{buf});
        }
    }

    friend class ZeekCollectable;

    /**
     * Fires the flare for prometheus-cpp callback handling and waits for it to complete.
     * This can be called from other threads to ensure the callback handling happens on
     * the main thread.
     */
    void WaitForPrometheusCallbacks();

private:
    RecordValPtr GetMetricOptsRecord(const prometheus::MetricFamily& metric_family);
    void BuildClusterJson();

    /**
     * Runs the Telemetry::sync() hook in Zeek script land.
     */
    void InvokeTelemetrySyncHook();

    /**
     * Runs the telemetry sync hooks and metric callbacks.
     */
    void UpdateMetrics();

    bool in_sync_hook = false;

    std::map<std::string, std::shared_ptr<MetricFamily>> families;
    std::map<std::string, RecordValPtr> opts_records;

    detail::process_stats current_process_stats;
    double process_stats_last_updated = 0.0;

    GaugePtr rss_gauge;
    GaugePtr vms_gauge;
    CounterPtr cpu_user_counter;
    CounterPtr cpu_system_counter;
    GaugePtr fds_gauge;
    GaugePtr process_start_time;

    std::shared_ptr<prometheus::Registry> prometheus_registry;
    std::unique_ptr<prometheus::Exposer> prometheus_exposer;

    std::string cluster_json;

    std::shared_ptr<ZeekCollectable> zeek_collectable;
    zeek::detail::Flare collector_flare;
    std::condition_variable collector_cv;
    std::mutex collector_cv_mtx;
    // Only modified under collector_cv_mtx!
    uint64_t collector_request_idx = 0;
    uint64_t collector_response_idx = 0;
};

} // namespace zeek::telemetry

namespace zeek {
extern telemetry::Manager* telemetry_mgr;

} // namespace zeek
