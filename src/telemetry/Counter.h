// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

#include "opentelemetry/sdk/metrics/sync_instruments.h"

namespace zeek::telemetry {

class DblCounterFamily;
class IntCounterFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter {
public:
    friend class IntCounterFamily;

    static inline const char* OpaqueName = "IntCounterMetricVal";

    IntCounter() = delete;
    IntCounter(const IntCounter&) noexcept = default;
    IntCounter& operator=(const IntCounter&) noexcept = default;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept {
        hdl->Add(1, attributes);
        value++;
    }

    /**
     * Increments the value by @p amount.
     * @pre `amount >= 0`
     */
    void Inc(uint64_t amount) noexcept {
        hdl->Add(amount, attributes);
        value += amount;
    }

    /**
     * Increments the value by 1.
     * @return The new value.
     */
    uint64_t operator++() noexcept {
        Inc();
        return value;
    }

    /**
     * @return The current value.
     */
    uint64_t Value() const noexcept { return value; }

    /**
     * @return Whether @c this and @p other refer to the same counter.
     */
    bool IsSameAs(const IntCounter& other) const noexcept { return hdl == other.hdl; }

    bool operator==(const IntCounter& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const IntCounter& rhs) const noexcept { return ! IsSameAs(rhs); }

private:
    using Handle = opentelemetry::metrics::Counter<uint64_t>;

    explicit IntCounter(opentelemetry::nostd::shared_ptr<Handle> hdl, Span<const LabelView> labels) noexcept;

    opentelemetry::nostd::shared_ptr<Handle> hdl;
    MetricAttributeIterable attributes;
    uint64_t value = 0;
};

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public MetricFamily {
public:
    friend class Manager;

    static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

    using InstanceType = IntCounter;

    IntCounterFamily(const IntCounterFamily&) noexcept = default;
    IntCounterFamily& operator=(const IntCounterFamily&) noexcept = default;

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    IntCounter GetOrAdd(Span<const LabelView> labels);

    /**
     * @copydoc GetOrAdd
     */
    IntCounter GetOrAdd(std::initializer_list<LabelView> labels) {
        return GetOrAdd(Span{labels.begin(), labels.size()});
    }

private:
    explicit IntCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                              std::string_view helptext, std::string_view unit = "1", bool is_sum = false);
};

/**
 * A handle to a metric that represents a floating point value that can only go
 * up.
 */
class DblCounter {
public:
    friend class DblCounterFamily;

    static inline const char* OpaqueName = "DblCounterMetricVal";

    DblCounter() = delete;
    DblCounter(const DblCounter&) noexcept = default;
    DblCounter& operator=(const DblCounter&) noexcept = default;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept {
        hdl->Add(1, attributes);
        value++;
    }

    /**
     * Increments the value by @p amount.
     * @pre `amount >= 0`
     */
    void Inc(double amount) noexcept {
        hdl->Add(amount, attributes);
        value += amount;
    }

    /**
     * @return The current value.
     */
    double Value() const noexcept { return value; }

    /**
     * @return Whether @c this and @p other refer to the same counter.
     */
    bool IsSameAs(const DblCounter& other) const noexcept { return hdl == other.hdl; }

    bool operator==(const DblCounter& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const DblCounter& rhs) const noexcept { return ! IsSameAs(rhs); }

private:
    using Handle = opentelemetry::metrics::Counter<double>;

    explicit DblCounter(opentelemetry::nostd::shared_ptr<Handle> hdl, Span<const LabelView> labels) noexcept;

    opentelemetry::nostd::shared_ptr<Handle> hdl;
    MetricAttributeIterable attributes;
    double value = 0;
};

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public MetricFamily {
public:
    friend class Manager;

    static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

    using InstanceType = DblCounter;

    DblCounterFamily(const DblCounterFamily&) noexcept = default;
    DblCounterFamily& operator=(const DblCounterFamily&) noexcept = default;

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    DblCounter GetOrAdd(Span<const LabelView> labels);

    /**
     * @copydoc GetOrAdd
     */
    DblCounter GetOrAdd(std::initializer_list<LabelView> labels) {
        return GetOrAdd(Span{labels.begin(), labels.size()});
    }

private:
    explicit DblCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                              std::string_view helptext, std::string_view unit = "1", bool is_sum = false);
};

namespace detail {

template<class T>
struct CounterOracle {
    static_assert(std::is_same<T, int64_t>::value, "Counter<T> only supports int64_t and double");

    using type = IntCounter;
};

template<>
struct CounterOracle<double> {
    using type = DblCounter;
};

} // namespace detail

template<class T>
using Counter = typename detail::CounterOracle<T>::type;

} // namespace zeek::telemetry
