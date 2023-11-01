// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "opentelemetry/sdk/metrics/sync_instruments.h"

namespace zeek::telemetry {
template<typename BaseType>
class BaseCounter {
public:
    using Handle = opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Counter<BaseType>>;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept { Inc(1); }

    /**
     * Increments the value by @p amount.
     * @pre `amount >= 0`
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

    BaseType Value() const noexcept { return value; }

    /**
     * @return Whether @c this and @p other refer to the same counter.
     */
    bool IsSameAs(const BaseCounter<BaseType>& other) const noexcept {
        return handle == other.handle && attributes == other.attributes;
    }

    bool operator==(const BaseCounter<BaseType>& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const BaseCounter<BaseType>& rhs) const noexcept { return ! IsSameAs(rhs); }

    bool CompareLabels(const Span<const LabelView>& labels) const { return attributes == labels; }

protected:
    explicit BaseCounter(Handle handle, Span<const LabelView> labels) noexcept
        : handle(std::move(handle)), attributes(labels) {}

    Handle handle;
    MetricAttributeIterable attributes;
    BaseType value = 0;
};

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter : public BaseCounter<uint64_t> {
public:
    static inline const char* OpaqueName = "IntCounterMetricVal";
    explicit IntCounter(Handle handle, Span<const LabelView> labels) noexcept
        : BaseCounter(std::move(handle), labels) {}
};

/**
 * A handle to a metric that represents an floating point value that can only go up.
 */
class DblCounter : public BaseCounter<double> {
public:
    static inline const char* OpaqueName = "DblCounterMetricVal";
    explicit DblCounter(Handle handle, Span<const LabelView> labels) noexcept
        : BaseCounter(std::move(handle), labels) {}
};

template<class CounterType, typename BaseType>
class BaseCounterFamily : public MetricFamily,
                          public std::enable_shared_from_this<BaseCounterFamily<CounterType, BaseType>> {
public:
    BaseCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                      std::string_view helptext, std::string_view unit = "1", bool is_sum = false)
        : MetricFamily(prefix, name, labels, helptext, unit, is_sum) {}

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    std::shared_ptr<CounterType> GetOrAdd(Span<const LabelView> labels) {
        if ( observable )
            // TODO: add some sort of warning here. You shouldn't ever add labeled handles to an
            // observable instrumen
            return nullptr;

        auto check = [&](const std::shared_ptr<CounterType>& counter) { return counter->CompareLabels(labels); };

        if ( auto it = std::find_if(counters.begin(), counters.end(), check); it != counters.end() )
            return *it;

        auto counter = std::make_shared<CounterType>(instrument, labels);
        counters.push_back(counter);
        return counter;
    }

    /**
     * @copydoc GetOrAdd
     */
    std::shared_ptr<CounterType> GetOrAdd(std::initializer_list<LabelView> labels) {
        return GetOrAdd(Span{labels.begin(), labels.size()});
    }

protected:
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Counter<BaseType>> instrument;
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObservableInstrument> observable;
    std::vector<std::shared_ptr<CounterType>> counters;
};

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public BaseCounterFamily<IntCounter, uint64_t> {
public:
    static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

    explicit IntCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                              std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                              opentelemetry::metrics::ObservableCallbackPtr callback = nullptr);

    IntCounterFamily(const IntCounterFamily&) noexcept = default;
    IntCounterFamily& operator=(const IntCounterFamily&) noexcept = default;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::INT_COUNTER; }
};

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public BaseCounterFamily<DblCounter, double> {
public:
    static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

    explicit DblCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                              std::string_view helptext, std::string_view unit = "1", bool is_sum = false,
                              opentelemetry::metrics::ObservableCallbackPtr callback = nullptr);

    DblCounterFamily(const DblCounterFamily&) noexcept = default;
    DblCounterFamily& operator=(const DblCounterFamily&) noexcept = default;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::DOUBLE_COUNTER; }
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
