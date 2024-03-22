// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
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
    void Inc(BaseType amount) noexcept { handle.Increment(amount); }

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
        auto metric = handle.Collect();
        return static_cast<BaseType>(metric.counter.value);
    }

    /**
     * Directly sets the value of the counter.
     */
    void Set(BaseType v) {
        handle.Reset();
        handle.Increment(v);
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
    explicit BaseCounter(FamilyType& family, const prometheus::Labels& labels,
                         prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : handle(family.Add(labels)), labels(labels) {
        if ( callback )
            handle.AddCollectCallback(callback);
    }

    Handle& handle;
    prometheus::Labels labels;
    BaseType last_value = 0;
};

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter : public BaseCounter<uint64_t> {
public:
    static inline const char* OpaqueName = "IntCounterMetricVal";
    explicit IntCounter(FamilyType& family, const prometheus::Labels& labels,
                        prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseCounter(family, labels, callback) {}
};

/**
 * A handle to a metric that represents an floating point value that can only go up.
 */
class DblCounter : public BaseCounter<double> {
public:
    static inline const char* OpaqueName = "DblCounterMetricVal";
    explicit DblCounter(FamilyType& family, const prometheus::Labels& labels,
                        prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseCounter(family, labels, callback) {}
};

template<class CounterType, typename BaseType>
class BaseCounterFamily : public MetricFamily,
                          public std::enable_shared_from_this<BaseCounterFamily<CounterType, BaseType>> {
public:
    BaseCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                      std::string_view helptext, std::shared_ptr<prometheus::Registry> registry,
                      std::string_view unit = "", bool is_sum = false)
        : MetricFamily(prefix, name, labels, helptext, unit, is_sum),
          family(prometheus::BuildCounter().Name(full_name).Help(std::string{helptext}).Register(*registry)) {}

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

    std::vector<std::shared_ptr<CounterType>>& GetAllCounters() { return counters; }

    std::vector<RecordValPtr> Collect() const override {
        static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
        static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
        static auto opts_idx = metric_record_type->FieldOffset("opts");
        static auto labels_idx = metric_record_type->FieldOffset("labels");
        static auto value_idx = metric_record_type->FieldOffset("value");
        static auto count_value_idx = metric_record_type->FieldOffset("count_value");

        RecordValPtr opts_record = GetMetricOptsRecord();

        std::vector<RecordValPtr> records;
        for ( const auto& ctr : counters ) {
            auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
            for ( const auto& [label_key, label] : ctr->Labels() ) {
                // We don't include the endpoint key/value unless it's a prometheus request
                if ( label_key != "endpoint" )
                    label_values_vec->Append(make_intrusive<StringVal>(label));
            }

            auto r = make_intrusive<zeek::RecordVal>(metric_record_type);
            r->Assign(labels_idx, label_values_vec);
            r->Assign(opts_idx, opts_record);

            if constexpr ( std::is_same_v<BaseType, double> )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(ctr->Value()));
            else {
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(static_cast<double>(ctr->Value())));
                r->Assign(count_value_idx, val_mgr->Count(ctr->Value()));
            }

            records.push_back(std::move(r));
        }

        return records;
    }

protected:
    prometheus::Family<prometheus::Counter>& family;
    std::vector<std::shared_ptr<CounterType>> counters;
};

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public BaseCounterFamily<IntCounter, uint64_t> {
public:
    static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

    explicit IntCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                              std::string_view helptext, std::shared_ptr<prometheus::Registry> registry,
                              std::string_view unit = "", bool is_sum = false)
        : BaseCounterFamily(prefix, name, labels, helptext, std::move(registry), unit, is_sum) {}

    IntCounterFamily(const IntCounterFamily&) noexcept = default;
    IntCounterFamily& operator=(const IntCounterFamily&) noexcept = delete;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::INT_COUNTER; }
};

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public BaseCounterFamily<DblCounter, double> {
public:
    static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

    explicit DblCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                              std::string_view helptext, std::shared_ptr<prometheus::Registry> registry,
                              std::string_view unit = "", bool is_sum = false)
        : BaseCounterFamily(prefix, name, labels, helptext, std::move(registry), unit, is_sum) {}

    DblCounterFamily(const DblCounterFamily&) noexcept = default;
    DblCounterFamily& operator=(const DblCounterFamily&) noexcept = delete;

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
