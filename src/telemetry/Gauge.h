// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

#include "opentelemetry/sdk/metrics/sync_instruments.h"

namespace zeek::telemetry {

class DblGaugeFamily;
class IntGaugeFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge {
public:
    friend class IntGaugeFamily;

    static inline const char* OpaqueName = "IntGaugeMetricVal";

    IntGauge() = delete;
    IntGauge(const IntGauge&) noexcept = default;
    IntGauge& operator=(const IntGauge&) noexcept = default;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept {
        hdl->Add(1, attributes);
        value++;
    }

    /**
     * Increments the value by @p amount.
     */
    void Inc(int64_t amount) noexcept {
        hdl->Add(amount, attributes);
        value += amount;
    }

    /**
     * Increments the value by 1.
     * @return The new value.
     */
    int64_t operator++() noexcept {
        Inc();
        return value;
    }

    /**
     * Decrements the value by 1.
     */
    void Dec() noexcept {
        hdl->Add(-1, attributes);
        value--;
    }

    /**
     * Decrements the value by @p amount.
     */
    void Dec(int64_t amount) noexcept {
        hdl->Add(amount * -1);
        value -= amount;
    }

    /**
     * Decrements the value by 1.
     * @return The new value.
     */
    int64_t operator--() noexcept {
        Dec();
        return value;
    }

    /**
     * @return The current value.
     */
    int64_t Value() const noexcept { return value; }

    /**
     * @return Whether @c this and @p other refer to the same counter.
     */
    bool IsSameAs(const IntGauge& other) const noexcept { return hdl == other.hdl; }

    bool operator==(const IntGauge& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const IntGauge& rhs) const noexcept { return ! IsSameAs(rhs); }

private:
    using Handle = opentelemetry::metrics::UpDownCounter<int64_t>;

    explicit IntGauge(opentelemetry::nostd::shared_ptr<Handle> hdl, Span<const LabelView> labels) noexcept;

    opentelemetry::nostd::shared_ptr<Handle> hdl;
    MetricAttributeIterable attributes;
    int64_t value = 0;
};

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily : public MetricFamily {
public:
    friend class Manager;

    static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

    using InstanceType = IntGauge;

    IntGaugeFamily(const IntGaugeFamily&) noexcept = default;
    IntGaugeFamily& operator=(const IntGaugeFamily&) noexcept = default;

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    IntGauge GetOrAdd(Span<const LabelView> labels);

    /**
     * @copydoc GetOrAdd
     */
    IntGauge GetOrAdd(std::initializer_list<LabelView> labels) { return GetOrAdd(Span{labels.begin(), labels.size()}); }

private:
    IntGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                   std::string_view helptext, std::string_view unit = "1", bool is_sum = false);
};

/**
 * A handle to a metric that represents a floating point value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class DblGauge {
public:
    friend class DblGaugeFamily;

    static inline const char* OpaqueName = "DblGaugeMetricVal";

    DblGauge() = delete;
    DblGauge(const DblGauge&) noexcept = default;
    DblGauge& operator=(const DblGauge&) noexcept = default;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept {
        hdl->Add(1, attributes);
        value++;
    }

    /**
     * Increments the value by @p amount.
     */
    void Inc(double amount) noexcept {
        hdl->Add(amount, attributes);
        value += amount;
    }

    /**
     * Increments the value by 1.
     */
    void Dec() noexcept {
        hdl->Add(-1, attributes);
        value--;
    }

    /**
     * Increments the value by @p amount.
     */
    void Dec(double amount) noexcept {
        hdl->Add(amount * -1, attributes);
        value -= amount;
    }

    /**
     * @return The current value.
     */
    double Value() const noexcept { return value; }

    /**
     * @return Whether @c this and @p other refer to the same counter.
     */
    bool IsSameAs(const DblGauge& other) const noexcept { return hdl == other.hdl; }

    bool operator==(const DblGauge& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const DblGauge& rhs) const noexcept { return ! IsSameAs(rhs); }

private:
    using Handle = opentelemetry::metrics::UpDownCounter<double>;

    explicit DblGauge(opentelemetry::nostd::shared_ptr<Handle> hdl, Span<const LabelView> labels) noexcept;

    opentelemetry::nostd::shared_ptr<Handle> hdl;
    MetricAttributeIterable attributes;
    double value = 0;
};

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily : public MetricFamily {
public:
    friend class Manager;

    static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

    using InstanceType = DblGauge;

    DblGaugeFamily(const DblGaugeFamily&) noexcept = default;
    DblGaugeFamily& operator=(const DblGaugeFamily&) noexcept = default;

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    DblGauge GetOrAdd(Span<const LabelView> labels);

    /**
     * @copydoc GetOrAdd
     */
    DblGauge GetOrAdd(std::initializer_list<LabelView> labels) { return GetOrAdd(Span{labels.begin(), labels.size()}); }

private:
    DblGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                   std::string_view helptext, std::string_view unit = "1", bool is_sum = false);
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
