// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "prometheus/family.h"
#include "prometheus/gauge.h"

namespace zeek::telemetry {

template<typename BaseType>
class BaseGauge {
public:
    using Handle = prometheus::Gauge;
    using FamilyType = prometheus::Family<Handle>;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept { Inc(1); }

    /**
     * Increments the value by @p amount.
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

    /**
     * Decrements the value by 1.
     */
    void Dec() noexcept { Dec(1); }

    /**
     * Decrements the value by @p amount.
     */
    void Dec(BaseType amount) noexcept { handle.Decrement(amount); }

    /**
     * Decrements the value by 1.
     * @return The new value.
     */
    int64_t operator--() noexcept {
        Dec(1);
        return Value();
    }

    BaseType Value() const noexcept {
        // Use Collect() here instead of Value() to correctly handle metrics
        // with callbacks.
        auto metric = handle.Collect();
        return static_cast<BaseType>(metric.gauge.value);
    }

    /**
     * Directly sets the value of the gauge.
     */
    void Set(BaseType v) { handle.Set(v); }

    /**
     * @return Whether @c this and @p other refer to the same gauge.
     */
    bool IsSameAs(const BaseGauge<BaseType>& other) const noexcept { return labels == other.labels; }

    bool operator==(const BaseGauge<BaseType>& rhs) const noexcept { return IsSameAs(rhs); }
    bool operator!=(const BaseGauge<BaseType>& rhs) const noexcept { return ! IsSameAs(rhs); }

    bool CompareLabels(const prometheus::Labels& lbls) const { return labels == lbls; }
    prometheus::Labels& Labels() { return labels; }

protected:
    explicit BaseGauge(FamilyType& family, const prometheus::Labels& labels,
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
 * A handle to a metric that represents an integer value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge : public BaseGauge<int64_t> {
public:
    static inline const char* OpaqueName = "IntGaugeMetricVal";

    explicit IntGauge(FamilyType& family, const prometheus::Labels& labels,
                      prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseGauge(family, labels, callback) {}

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

    explicit DblGauge(FamilyType& family, const prometheus::Labels& labels,
                      prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseGauge(family, labels, callback) {}

    DblGauge(const DblGauge&) = delete;
    DblGauge& operator=(const DblGauge&) = delete;
};

template<class GaugeType, typename BaseType>
class BaseGaugeFamily : public MetricFamily, public std::enable_shared_from_this<BaseGaugeFamily<GaugeType, BaseType>> {
public:
    BaseGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                    std::string_view helptext, std::shared_ptr<prometheus::Registry> registry,
                    std::string_view unit = "", bool is_sum = false)
        : MetricFamily(prefix, name, labels, helptext, unit, is_sum),
          family(prometheus::BuildGauge().Name(full_name).Help(std::string{helptext}).Register(*registry)) {}

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    std::shared_ptr<GaugeType> GetOrAdd(Span<const LabelView> labels,
                                        prometheus::CollectCallbackPtr callback = nullptr) {
        prometheus::Labels p_labels = BuildPrometheusLabels(labels);

        auto check = [&](const std::shared_ptr<GaugeType>& gauge) { return gauge->CompareLabels(p_labels); };

        if ( auto it = std::find_if(gauges.begin(), gauges.end(), check); it != gauges.end() )
            return *it;

        auto gauge = std::make_shared<GaugeType>(family, p_labels, callback);
        gauges.push_back(gauge);
        return gauge;
    }

    /**
     * @copydoc GetOrAdd
     */
    std::shared_ptr<GaugeType> GetOrAdd(std::initializer_list<LabelView> labels,
                                        prometheus::CollectCallbackPtr callback = nullptr) {
        return GetOrAdd(Span{labels.begin(), labels.size()}, callback);
    }

    std::vector<std::shared_ptr<GaugeType>>& GetAllGauges() { return gauges; }

    std::vector<RecordValPtr> Collect() const override {
        static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
        static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
        static auto opts_idx = metric_record_type->FieldOffset("opts");
        static auto labels_idx = metric_record_type->FieldOffset("labels");
        static auto value_idx = metric_record_type->FieldOffset("value");
        static auto count_value_idx = metric_record_type->FieldOffset("count_value");

        RecordValPtr opts_record = GetMetricOptsRecord();

        std::vector<RecordValPtr> records;
        for ( const auto& g : gauges ) {
            auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
            for ( const auto& [label_key, label] : g->Labels() ) {
                // We don't include the endpoint key/value unless it's a prometheus request
                if ( label_key != "endpoint" )
                    label_values_vec->Append(make_intrusive<StringVal>(label));
            }

            auto r = make_intrusive<zeek::RecordVal>(metric_record_type);
            r->Assign(labels_idx, label_values_vec);
            r->Assign(opts_idx, opts_record);

            if constexpr ( std::is_same_v<BaseType, double> )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(g->Value()));
            else {
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(static_cast<double>(g->Value())));
                r->Assign(count_value_idx, val_mgr->Count(g->Value()));
            }

            records.push_back(std::move(r));
        }

        return records;
    }

protected:
    prometheus::Family<prometheus::Gauge>& family;
    std::vector<std::shared_ptr<GaugeType>> gauges;
};

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily : public BaseGaugeFamily<IntGauge, int64_t> {
public:
    static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

    IntGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                   std::string_view helptext, std::shared_ptr<prometheus::Registry> registry,
                   std::string_view unit = "", bool is_sum = false)
        : BaseGaugeFamily(prefix, name, labels, helptext, std::move(registry), unit, is_sum) {}

    IntGaugeFamily(const IntGaugeFamily&) noexcept = default;
    IntGaugeFamily& operator=(const IntGaugeFamily&) noexcept = delete;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::INT_GAUGE; }
};

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily : public BaseGaugeFamily<DblGauge, double> {
public:
    static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

    DblGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                   std::string_view helptext, std::shared_ptr<prometheus::Registry> registry,
                   std::string_view unit = "", bool is_sum = false)
        : BaseGaugeFamily(prefix, name, labels, helptext, std::move(registry), unit, is_sum) {}

    DblGaugeFamily(const DblGaugeFamily&) noexcept = default;
    DblGaugeFamily& operator=(const DblGaugeFamily&) noexcept = delete;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::DOUBLE_GAUGE; }
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
