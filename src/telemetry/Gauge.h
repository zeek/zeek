// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <memory>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/Utils.h"
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
    explicit BaseGauge(FamilyType* family, const prometheus::Labels& labels,
                       prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : handle(family->Add(labels)), labels(labels) {
        if ( callback )
            handle.AddCollectCallback(callback);
    }

    Handle& handle;
    prometheus::Labels labels;
};

/**
 * A handle to a metric that represents an integer value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge final : public BaseGauge<int64_t> {
public:
    static inline const char* OpaqueName = "IntGaugeMetricVal";

    explicit IntGauge(FamilyType* family, const prometheus::Labels& labels,
                      prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseGauge(family, labels, callback) {}

    IntGauge(const IntGauge&) = delete;
    IntGauge& operator=(const IntGauge&) = delete;
};

/**
 * A handle to a metric that represents an double value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class DblGauge final : public BaseGauge<double> {
public:
    static inline const char* OpaqueName = "DblGaugeMetricVal";

    explicit DblGauge(FamilyType* family, const prometheus::Labels& labels,
                      prometheus::CollectCallbackPtr callback = nullptr) noexcept
        : BaseGauge(family, labels, callback) {}

    DblGauge(const DblGauge&) = delete;
    DblGauge& operator=(const DblGauge&) = delete;
};

template<class GaugeType, typename BaseType>
class BaseGaugeFamily : public MetricFamily, public std::enable_shared_from_this<BaseGaugeFamily<GaugeType, BaseType>> {
public:
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

protected:
    BaseGaugeFamily(prometheus::Family<prometheus::Gauge>* family, Span<const std::string_view> labels)
        : MetricFamily(labels), family(family) {}

    prometheus::Family<prometheus::Gauge>* family;
    std::vector<std::shared_ptr<GaugeType>> gauges;
};

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily final : public BaseGaugeFamily<IntGauge, int64_t> {
public:
    static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

    explicit IntGaugeFamily(prometheus::Family<prometheus::Gauge>* family, Span<const std::string_view> labels)
        : BaseGaugeFamily(family, labels) {}

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::INT_GAUGE; }
};

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily final : public BaseGaugeFamily<DblGauge, double> {
public:
    static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

    explicit DblGaugeFamily(prometheus::Family<prometheus::Gauge>* family, Span<const std::string_view> labels)
        : BaseGaugeFamily(family, labels) {}

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
