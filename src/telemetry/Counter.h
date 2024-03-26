// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <memory>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/Utils.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "prometheus/counter.h"
#include "prometheus/family.h"

namespace zeek::telemetry {

template<typename BaseType>
class BaseCounter {
public:
    using Handle = prometheus::Counter;
    using FamilyType = prometheus::Family<Handle>;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept { Inc(1); }

    /**
     * Increments the value by @p amount.
     * @pre `amount >= 0`
     */
    void Inc(BaseType amount) noexcept { handle->Increment(amount); }

    /**
     * Increments the value by 1.
     * @return The new value.
     */
    BaseType operator++() noexcept {
        Inc(1);
        return Value();
    }

    BaseType Value() const noexcept {
        // Use Collect() here instead of Value() to correctly handle metrics with
        // callbacks.
        auto metric = handle->Collect();
        return static_cast<BaseType>(metric.counter.value);
    }

    /**
     * Directly sets the value of the counter.
     */
    void Set(BaseType v) {
        handle->Reset();
        handle->Increment(v);
    }

    /**
     * @return Whether @c this and @p other refer to the same counter.
     */
    bool IsSameAs(const BaseCounter<BaseType>& other) const noexcept { return labels == other.labels; }

    bool operator==(const BaseCounter<BaseType>& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const BaseCounter<BaseType>& rhs) const noexcept { return ! IsSameAs(rhs); }

    bool CompareLabels(const prometheus::Labels& lbls) const { return labels == lbls; }
    prometheus::Labels& Labels() { return labels; }

protected:
    explicit BaseCounter(FamilyType* family, const prometheus::Labels& labels,
                         prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : handle(&(family->Add(labels))), labels(labels) {
        if ( callback )
            handle->AddCollectCallback(callback);
    }

    Handle* handle;
    prometheus::Labels labels;
};

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter final : public BaseCounter<uint64_t> {
public:
    static inline const char* OpaqueName = "IntCounterMetricVal";
    explicit IntCounter(FamilyType* family, const prometheus::Labels& labels,
                        prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseCounter(family, labels, callback) {}
};

/**
 * A handle to a metric that represents an floating point value that can only go up.
 */
class DblCounter final : public BaseCounter<double> {
public:
    static inline const char* OpaqueName = "DblCounterMetricVal";
    explicit DblCounter(FamilyType* family, const prometheus::Labels& labels,
                        prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseCounter(family, labels, callback) {}
};

template<class CounterType, typename BaseType>
class BaseCounterFamily : public MetricFamily,
                          public std::enable_shared_from_this<BaseCounterFamily<CounterType, BaseType>> {
public:
    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    std::shared_ptr<CounterType> GetOrAdd(Span<const LabelView> labels,
                                          prometheus::CollectCallbackPtr callback = nullptr) {
        prometheus::Labels p_labels = BuildPrometheusLabels(labels);

        auto check = [&](const std::shared_ptr<CounterType>& counter) { return counter->CompareLabels(p_labels); };

        if ( auto it = std::find_if(counters.begin(), counters.end(), check); it != counters.end() )
            return *it;

        auto counter = std::make_shared<CounterType>(family, p_labels, callback);
        counters.push_back(counter);
        return counter;
    }

    /**
     * @copydoc GetOrAdd
     */
    std::shared_ptr<CounterType> GetOrAdd(std::initializer_list<LabelView> labels,
                                          prometheus::CollectCallbackPtr callback = nullptr) {
        return GetOrAdd(Span{labels.begin(), labels.size()}, callback);
    }

protected:
    BaseCounterFamily(prometheus::Family<prometheus::Counter>* family, Span<const std::string_view> labels)
        : MetricFamily(labels), family(family) {}

    prometheus::Family<prometheus::Counter>* family;
    std::vector<std::shared_ptr<CounterType>> counters;
};

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily final : public BaseCounterFamily<IntCounter, uint64_t> {
public:
    static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

    explicit IntCounterFamily(prometheus::Family<prometheus::Counter>* family, Span<const std::string_view> labels)
        : BaseCounterFamily(family, labels) {}

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::INT_COUNTER; }
};

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily final : public BaseCounterFamily<DblCounter, double> {
public:
    static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

    explicit DblCounterFamily(prometheus::Family<prometheus::Counter>* family, Span<const std::string_view> labels)
        : BaseCounterFamily(family, labels) {}

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
