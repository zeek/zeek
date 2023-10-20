// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

#include "opentelemetry/sdk/metrics/async_instruments.h"
#include "opentelemetry/sdk/metrics/sync_instruments.h"

namespace zeek::telemetry {

template<typename BaseType>
class BaseGauge {
public:
    using Handle = opentelemetry::nostd::shared_ptr<opentelemetry::metrics::UpDownCounter<BaseType>>;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept { Inc(1); }

    /**
     * Increments the value by @p amount.
     */
    void Inc(BaseType amount) noexcept {
        handle->Add(amount, attributes);
        value += amount;
    }

    /**
     * Increments the value by 1.
     * @return The new value.
     */
    BaseType operator++() noexcept {
        Inc(1);
        return value;
    }

    /**
     * Decrements the value by 1.
     */
    void Dec() noexcept { Dec(1); }

    /**
     * Decrements the value by @p amount.
     */
    void Dec(BaseType amount) noexcept {
        handle->Add(amount * -1, attributes);
        value -= amount;
    }

    /**
     * Decrements the value by 1.
     * @return The new value.
     */
    int64_t operator--() noexcept {
        Dec(1);
        return value;
    }

    BaseType Value() const noexcept { return value; }

    /**
     * @return Whether @c this and @p other refer to the same counter.
     */
    bool IsSameAs(const BaseGauge<BaseType>& other) const noexcept {
        return handle == other.handle && attributes == other.attributes;
    }

    bool operator==(const BaseGauge<BaseType>& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const BaseGauge<BaseType>& rhs) const noexcept { return ! IsSameAs(rhs); }

    bool CompareLabels(const Span<const LabelView>& labels) const { return attributes == labels; }

protected:
    explicit BaseGauge(Handle handle, Span<const LabelView> labels) noexcept
        : handle(std::move(handle)), attributes(labels) {}

    Handle handle;
    MetricAttributeIterable attributes;
    BaseType value = 0;
};

/**
 * A handle to a metric that represents an integer value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge : public BaseGauge<int64_t> {
public:
    static inline const char* OpaqueName = "IntGaugeMetricVal";

    explicit IntGauge(Handle handle, Span<const LabelView> labels) noexcept : BaseGauge(std::move(handle), labels) {}

    IntGauge(const IntGauge&) = delete;
    IntGauge& operator=(const IntGauge&) = delete;
};

/**
 * A handle to a metric that represents an double value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class DblGauge : public BaseGauge<double> {
public:
    static inline const char* OpaqueName = "DblGaugeMetricVal";

    explicit DblGauge(Handle handle, Span<const LabelView> labels) noexcept : BaseGauge(std::move(handle), labels) {}

    DblGauge(const DblGauge&) = delete;
    DblGauge& operator=(const DblGauge&) = delete;
};

template<class GaugeType, typename BaseType>
class BaseGaugeFamily : public MetricFamily, public std::enable_shared_from_this<BaseGaugeFamily<GaugeType, BaseType>> {
public:
    BaseGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                    std::string_view helptext, std::string_view unit = "1", bool is_sum = false)
        : MetricFamily(prefix, name, labels, helptext, unit, is_sum) {}

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    std::shared_ptr<GaugeType> GetOrAdd(Span<const LabelView> labels) {
        auto check = [&](const std::shared_ptr<GaugeType>& gauge) { return gauge->CompareLabels(labels); };

        if ( auto it = std::find_if(gauges.begin(), gauges.end(), check); it != gauges.end() )
            return *it;

        auto gauge = std::make_shared<GaugeType>(instrument, labels);
        gauges.push_back(gauge);
        return gauge;
    }

    /**
     * @copydoc GetOrAdd
     */
    std::shared_ptr<GaugeType> GetOrAdd(std::initializer_list<LabelView> labels) {
        return GetOrAdd(Span{labels.begin(), labels.size()});
    }

protected:
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::UpDownCounter<BaseType>> instrument;
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObservableInstrument> observable;
    std::vector<std::shared_ptr<GaugeType>> gauges;
};

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily : public BaseGaugeFamily<IntGauge, int64_t> {
public:
    static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

    IntGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                   std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                   opentelemetry::metrics::ObservableCallbackPtr callback = nullptr);

    IntGaugeFamily(const IntGaugeFamily&) noexcept = default;
    IntGaugeFamily& operator=(const IntGaugeFamily&) noexcept = default;
};

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily : public BaseGaugeFamily<DblGauge, double> {
public:
    static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

    DblGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                   std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                   opentelemetry::metrics::ObservableCallbackPtr callback = nullptr);

    DblGaugeFamily(const DblGaugeFamily&) noexcept = default;
    DblGaugeFamily& operator=(const DblGaugeFamily&) noexcept = default;
};

namespace detail {

template<class T>
struct GaugeOracle {
    static_assert(std::is_same<T, int64_t>::value, "Gauge<T> only supports int64_t and double");

    using type = IntGauge;
};

template<>
struct GaugeOracle<double> {
    using type = DblGauge;
};

} // namespace detail

template<class T>
using Gauge = typename detail::GaugeOracle<T>::type;

} // namespace zeek::telemetry
