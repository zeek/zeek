// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

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

namespace zeek {
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
} // namespace zeek

namespace zeek::telemetry {

class OtelReader;

/**
 * Manages a collection of metric families.
 */
class Manager final {
public:
    Manager();

    Manager(const Manager&) = delete;

    Manager& operator=(const Manager&) = delete;

    ~Manager();

    /**
     * Initialization of the manager. This is called late during Zeek's
     * initialization after any scripts are processed.
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
     * @param callback Passing a callback method will enable asynchronous mode. The callback method will be called by
     * the metrics subsystem whenever data is requested.
     */
    template<class ValueType = int64_t>
    auto CounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                       std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                       opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        auto fam = LookupFamily(prefix, name);

        if constexpr ( std::is_same<ValueType, int64_t>::value ) {
            if ( fam )
                return std::static_pointer_cast<IntCounterFamily>(fam);

            auto int_fam = std::make_shared<IntCounterFamily>(prefix, name, labels, helptext, unit, is_sum, callback);
            families.push_back(int_fam);
            return int_fam;
        }
        else {
            static_assert(std::is_same<ValueType, double>::value, "metrics only support int64_t and double values");

            if ( fam )
                return std::static_pointer_cast<DblCounterFamily>(fam);

            auto dbl_fam = std::make_shared<DblCounterFamily>(prefix, name, labels, helptext, unit, is_sum, callback);
            families.push_back(dbl_fam);
            return dbl_fam;
        }
    }

    /// @copydoc CounterFamily
    template<class ValueType = int64_t>
    auto CounterFamily(std::string_view prefix, std::string_view name, std::initializer_list<std::string_view> labels,
                       std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                       opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        auto lbl_span = Span{labels.begin(), labels.size()};
        return CounterFamily<ValueType>(prefix, name, lbl_span, helptext, unit, is_sum, callback);
    }

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
    template<class ValueType = int64_t>
    Counter<ValueType> CounterInstance(std::string_view prefix, std::string_view name, Span<const LabelView> labels,
                                       std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                                       opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        return WithLabelNames(labels, [&, this](auto labelNames) {
            auto family = CounterFamily<ValueType>(prefix, name, labelNames, helptext, unit, is_sum, callback);
            return family.getOrAdd(labels);
        });
    }

    /// @copydoc counterInstance
    template<class ValueType = int64_t>
    Counter<ValueType> CounterInstance(std::string_view prefix, std::string_view name,
                                       std::initializer_list<LabelView> labels, std::string_view helptext,
                                       std::string_view unit = "1", bool is_sum = false,
                                       opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        auto lbl_span = Span{labels.begin(), labels.size()};
        return CounterInstance<ValueType>(prefix, name, lbl_span, helptext, unit, is_sum, callback);
    }

    /**
     * @return A gauge metric family. Creates the family lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Names for all label dimensions of the metric.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement.
     * @param is_sum Indicates whether this metric accumulates something, where only the total value is of interest.
     * @param callback Passing a callback method will enable asynchronous mode. The callback method will be called by
     * the metrics subsystem whenever data is requested.
     */
    template<class ValueType = int64_t>
    auto GaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                     std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                     opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        auto fam = LookupFamily(prefix, name);

        if constexpr ( std::is_same<ValueType, int64_t>::value ) {
            if ( fam )
                return std::static_pointer_cast<IntGaugeFamily>(fam);

            auto int_fam = std::make_shared<IntGaugeFamily>(prefix, name, labels, helptext, unit, is_sum, callback);
            families.push_back(int_fam);
            return int_fam;
        }
        else {
            static_assert(std::is_same<ValueType, double>::value, "metrics only support int64_t and double values");
            if ( fam )
                return std::static_pointer_cast<DblGaugeFamily>(fam);

            auto dbl_fam = std::make_shared<DblGaugeFamily>(prefix, name, labels, helptext, unit, is_sum, callback);
            families.push_back(dbl_fam);
            return dbl_fam;
        }
    }

    /// @copydoc GaugeFamily
    template<class ValueType = int64_t>
    auto GaugeFamily(std::string_view prefix, std::string_view name, std::initializer_list<std::string_view> labels,
                     std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                     opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        auto lbl_span = Span{labels.begin(), labels.size()};
        return GaugeFamily<ValueType>(prefix, name, lbl_span, helptext, unit, is_sum, callback);
    }

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
    template<class ValueType = int64_t>
    std::shared_ptr<Gauge<ValueType>> GaugeInstance(std::string_view prefix, std::string_view name,
                                                    Span<const LabelView> labels, std::string_view helptext,
                                                    std::string_view unit = "1", bool is_sum = false,
                                                    opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        return WithLabelNames(labels, [&, this](auto labelNames) {
            auto family = GaugeFamily<ValueType>(prefix, name, labelNames, helptext, unit, is_sum, callback);
            return family->GetOrAdd(labels);
        });
    }

    /// @copydoc GaugeInstance
    template<class ValueType = int64_t>
    std::shared_ptr<Gauge<ValueType>> GaugeInstance(std::string_view prefix, std::string_view name,
                                                    std::initializer_list<LabelView> labels, std::string_view helptext,
                                                    std::string_view unit = "1", bool is_sum = false,
                                                    opentelemetry::metrics::ObservableCallbackPtr callback = nullptr) {
        auto lbl_span = Span{labels.begin(), labels.size()};
        return GaugeInstance<ValueType>(prefix, name, lbl_span, helptext, unit, is_sum, callback);
    }

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
     * @param default_upper_bounds Upper bounds for the metric buckets.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement. Please use base units such as `bytes` or
     *             `seconds` (prefer lowercase). The pseudo-unit `1` identifies
     *             dimensionless counts.
     * @param is_sum Setting this to `true` indicates that this metric adds
     *               something up to a total, where only the total value is of
     *               interest. For example, the total number of HTTP requests.
     * @note The first call wins when calling this function multiple times with
     *       different bucket settings. Users may also override
     *       @p default_upper_bounds via run-time configuration.
     */
    template<class ValueType = int64_t>
    auto HistogramFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                         ConstSpan<ValueType> default_upper_bounds, std::string_view helptext,
                         std::string_view unit = "1", bool is_sum = false) {
        auto fam = LookupFamily(prefix, name);

        if constexpr ( std::is_same<ValueType, int64_t>::value ) {
            if ( fam )
                return std::static_pointer_cast<IntHistogramFamily>(fam);

            auto int_fam = std::make_shared<IntHistogramFamily>(prefix, name, labels, default_upper_bounds, helptext,
                                                                unit, is_sum);
            families.push_back(int_fam);
            return int_fam;
        }
        else {
            static_assert(std::is_same<ValueType, double>::value, "metrics only support int64_t and double values");
            if ( fam )
                return std::static_pointer_cast<DblHistogramFamily>(fam);

            auto dbl_fam = std::make_shared<DblHistogramFamily>(prefix, name, labels, default_upper_bounds, helptext,
                                                                unit, is_sum);
            families.push_back(dbl_fam);
            return dbl_fam;
        }
    }

    /// @copydoc HistogramFamily
    template<class ValueType = int64_t>
    auto HistogramFamily(std::string_view prefix, std::string_view name, std::initializer_list<std::string_view> labels,
                         ConstSpan<ValueType> default_upper_bounds, std::string_view helptext,
                         std::string_view unit = "1", bool is_sum = false) {
        auto lbl_span = Span{labels.begin(), labels.size()};
        return HistogramFamily<ValueType>(prefix, name, lbl_span, default_upper_bounds, helptext, unit, is_sum);
    }

    /**
     * Returns a histogram. Creates the family lazily if necessary.
     * @param prefix The prefix (namespace) this family belongs to. Usually the
     *               application or protocol name, e.g., `http`. The prefix `caf`
     *               as well as prefixes starting with an underscore are
     *               reserved.
     * @param name The human-readable name of the metric, e.g., `requests`.
     * @param labels Names for all label dimensions of the metric.
     * @param default_upper_bounds Upper bounds for the metric buckets.
     * @param helptext Short explanation of the metric.
     * @param unit Unit of measurement. Please use base units such as `bytes` or
     *             `seconds` (prefer lowercase). The pseudo-unit `1` identifies
     *             dimensionless counts.
     * @param is_sum Setting this to `true` indicates that this metric adds
     *               something up to a total, where only the total value is of
     *               interest. For example, the total number of HTTP requests.
     * @note The first call wins when calling this function multiple times with
     *       different bucket settings. Users may also override
     *       @p default_upper_bounds via run-time configuration.
     */
    template<class ValueType = int64_t>
    Histogram<ValueType> HistogramInstance(std::string_view prefix, std::string_view name, Span<const LabelView> labels,
                                           ConstSpan<ValueType> default_upper_bounds, std::string_view helptext,
                                           std::string_view unit = "1", bool is_sum = false) {
        return WithLabelNames(labels, [&, this](auto labelNames) {
            auto family =
                HistogramFamily<ValueType>(prefix, name, labelNames, default_upper_bounds, helptext, unit, is_sum);
            return family.getOrAdd(labels);
        });
    }

    /// @copdoc HistogramInstance
    template<class ValueType = int64_t>
    Histogram<ValueType> HistogramInstance(std::string_view prefix, std::string_view name,
                                           std::initializer_list<LabelView> labels,
                                           ConstSpan<ValueType> default_upper_bounds, std::string_view helptext,
                                           std::string_view unit = "1", bool is_sum = false) {
        auto lbls = Span{labels.begin(), labels.size()};
        return HistogramInstance(prefix, name, lbls, default_upper_bounds, helptext, unit, is_sum);
    }

    static void FetchSystemStats(opentelemetry::metrics::ObserverResult observer_result, void* state);

    /**
     * Adds a view to the MeterProvider.
     */
    void AddView(const std::string& name, const std::string& helptext, const std::string& unit,
                 opentelemetry::sdk::metrics::InstrumentType instrument_type,
                 opentelemetry::sdk::metrics::AggregationType aggregation);

protected:
    template<class F>
    static void WithLabelNames(Span<const LabelView> xs, F continuation) {
        if ( xs.size() <= 10 ) {
            std::string_view buf[10];
            for ( size_t index = 0; index < xs.size(); ++index )
                buf[index] = xs[index].first;

            return continuation(Span{buf, xs.size()});
        }
        else {
            std::vector<std::string_view> buf;
            for ( auto x : xs )
                buf.emplace_back(x.first, x.second);

            return continuation(Span{buf});
        }
    }

private:
    std::shared_ptr<MetricFamily> LookupFamily(std::string_view prefix, std::string_view name) const;

    std::string metrics_name;
    std::string metrics_version;
    std::string metrics_schema;

    std::shared_ptr<OtelReader> otel_reader;
    std::vector<std::shared_ptr<MetricFamily>> families;
};

} // namespace zeek::telemetry

namespace zeek {

extern telemetry::Manager* telemetry_mgr;

} // namespace zeek
