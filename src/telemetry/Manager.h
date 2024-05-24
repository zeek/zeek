// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <condition_variable>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string_view>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Span.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"
#include "zeek/telemetry/Histogram.h"
#include "zeek/telemetry/ProcessStats.h"
#include "zeek/telemetry/Utils.h"

namespace zeek {
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
} // namespace zeek

namespace zeek::telemetry {

/**
 * Manages a collection of metric families.
 */
class Manager final {
public:
    Manager();

    Manager(const Manager&) = delete;

    Manager& operator=(const Manager&) = delete;

    ~Manager() = default;

    /**
     * Initialization of the manager. This is called late during Zeek's
     * initialization after any scripts are processed. Sets up the Prometheus
     * server and the process stats metrics, and on a manager node will enable
     * the Prometheus service discovery endpoint.
     */
    void InitPostScript();

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
     * @param is_sum Indicates whether this metric accumulates something, where only the total value is of interest.
     */
    std::shared_ptr<telemetry::CounterFamily> CounterFamily(std::string_view prefix, std::string_view name,
                                                            Span<const std::string_view> labels,
                                                            std::string_view helptext, std::string_view unit = "",
                                                            bool is_sum = false);

    /// @copydoc CounterFamily
    std::shared_ptr<telemetry::CounterFamily> CounterFamily(std::string_view prefix, std::string_view name,
                                                            std::initializer_list<std::string_view> labels,
                                                            std::string_view helptext, std::string_view unit = "",
                                                            bool is_sum = false);

    /**
     * Accesses a counter instance. Creates the hosting metric family as well
     * as the counter lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Values for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     * @param is_sum Indicates whether this metric accumulates something, where only the total value is of interest.
     * @param callback Passing a callback method will enable asynchronous mode. The callback method will be called by
     * the metrics subsystem whenever data is requested.
     */
    std::shared_ptr<Counter> CounterInstance(std::string_view prefix, std::string_view name,
                                             Span<const LabelView> labels, std::string_view helptext,
                                             std::string_view unit = "", bool is_sum = false,
                                             prometheus::CollectCallbackPtr callback = nullptr);

    /// @copydoc counterInstance
    std::shared_ptr<Counter> CounterInstance(std::string_view prefix, std::string_view name,
                                             std::initializer_list<LabelView> labels, std::string_view helptext,
                                             std::string_view unit = "", bool is_sum = false,
                                             prometheus::CollectCallbackPtr callback = nullptr);

    /**
     * @return A gauge metric family. Creates the family lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Names for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     * @param is_sum Indicates whether this metric accumulates something, where only the total value is of interest.
     */
    std::shared_ptr<telemetry::GaugeFamily> GaugeFamily(std::string_view prefix, std::string_view name,
                                                        Span<const std::string_view> labels, std::string_view helptext,
                                                        std::string_view unit = "", bool is_sum = false);

    /// @copydoc GaugeFamily
    std::shared_ptr<telemetry::GaugeFamily> GaugeFamily(std::string_view prefix, std::string_view name,
                                                        std::initializer_list<std::string_view> labels,
                                                        std::string_view helptext, std::string_view unit = "",
                                                        bool is_sum = false);

    /**
     * Accesses a gauge instance. Creates the hosting metric family as well
     * as the gauge lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Values for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     * @param is_sum Indicates whether this metric accumulates something, where only the total value is of interest.
     * @param callback Passing a callback method will enable asynchronous mode. The callback method will be called by
     * the metrics subsystem whenever data is requested.
     */
    std::shared_ptr<Gauge> GaugeInstance(std::string_view prefix, std::string_view name, Span<const LabelView> labels,
                                         std::string_view helptext, std::string_view unit = "", bool is_sum = false,
                                         prometheus::CollectCallbackPtr callback = nullptr);

    /// @copydoc GaugeInstance
    std::shared_ptr<Gauge> GaugeInstance(std::string_view prefix, std::string_view name,
                                         std::initializer_list<LabelView> labels, std::string_view helptext,
                                         std::string_view unit = "", bool is_sum = false,
                                         prometheus::CollectCallbackPtr callback = nullptr);

    // Forces the compiler to use the type `Span<const T>` instead of trying to
    // match parameters to a `span`.
    template<class T>
    struct ConstSpanOracle {
        using Type = Span<const T>;
    };

    // Convenience alias to safe some typing.
    template<class T>
    using ConstSpan = typename ConstSpanOracle<T>::Type;

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
    std::shared_ptr<telemetry::HistogramFamily> HistogramFamily(std::string_view prefix, std::string_view name,
                                                                Span<const std::string_view> labels,
                                                                ConstSpan<double> bounds, std::string_view helptext,
                                                                std::string_view unit = "");

    /// @copydoc HistogramFamily
    std::shared_ptr<telemetry::HistogramFamily> HistogramFamily(std::string_view prefix, std::string_view name,
                                                                std::initializer_list<std::string_view> labels,
                                                                ConstSpan<double> bounds, std::string_view helptext,
                                                                std::string_view unit = "");

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
    std::shared_ptr<Histogram> HistogramInstance(std::string_view prefix, std::string_view name,
                                                 Span<const LabelView> labels, ConstSpan<double> bounds,
                                                 std::string_view helptext, std::string_view unit = "");

    /// @copdoc HistogramInstance
    std::shared_ptr<Histogram> HistogramInstance(std::string_view prefix, std::string_view name,
                                                 std::initializer_list<LabelView> labels,
                                                 std::initializer_list<double> bounds, std::string_view helptext,
                                                 std::string_view unit = "");

    /**
     * @return A JSON description of the cluster configuration for reporting
     * to Prometheus for service discovery requests.
     */
    std::string GetClusterJson() const;

    /**
     * @return The pointer to the prometheus-cpp registry used by the telemetry
     * manager. This is public so that third parties (such as broker) can add
     * elements to it directly.
     */
    std::shared_ptr<prometheus::Registry> GetRegistry() const { return prometheus_registry; }

protected:
    template<class F>
    static auto WithLabelNames(Span<const LabelView> xs, F continuation) {
        if ( xs.size() <= 10 ) {
            std::string_view buf[10];
            for ( size_t index = 0; index < xs.size(); ++index )
                buf[index] = xs[index].first;

            return continuation(Span{buf, xs.size()});
        }
        else {
            std::vector<std::string_view> buf;
            for ( auto x : xs )
                buf.emplace_back(x.first);

            return continuation(Span{buf});
        }
    }

private:
    RecordValPtr GetMetricOptsRecord(const prometheus::MetricFamily& metric_family);

    std::map<std::string, std::shared_ptr<MetricFamily>> families;
    std::map<std::string, RecordValPtr> opts_records;

    detail::process_stats current_process_stats;
    double process_stats_last_updated = 0.0;

    std::shared_ptr<Gauge> rss_gauge;
    std::shared_ptr<Gauge> vms_gauge;
    std::shared_ptr<Gauge> cpu_gauge;
    std::shared_ptr<Gauge> fds_gauge;

    std::string endpoint_name;
    std::vector<std::string> export_prefixes;

    std::shared_ptr<prometheus::Registry> prometheus_registry;
    std::unique_ptr<prometheus::Exposer> prometheus_exposer;
};

} // namespace zeek::telemetry

namespace zeek {
extern telemetry::Manager* telemetry_mgr;

} // namespace zeek
