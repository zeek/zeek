// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <prometheus/family.h>
#include <prometheus/gauge.h>
#include <cstdint>
#include <initializer_list>
#include <memory>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/Utils.h"
#include "zeek/telemetry/telemetry.bif.h"

namespace zeek::telemetry {

/**
 * A handle to a metric that can count up and down.
 */
class Gauge {
public:
    static inline const char* OpaqueName = "GaugeMetricVal";

    using Handle = prometheus::Gauge;
    using FamilyType = prometheus::Family<Handle>;

    explicit Gauge(FamilyType* family, const prometheus::Labels& labels,
                   prometheus::CollectCallbackPtr callback = nullptr) noexcept;

    /**
     * Increments the value by 1.
     */
    void Inc() noexcept { Inc(1); }

    /**
     * Increments the value by @p amount.
     */
    void Inc(double amount) noexcept { handle.Increment(amount); }

    /**
     * Increments the value by 1.
     * @return The new value.
     */
    double operator++() noexcept {
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
    void Dec(double amount) noexcept { handle.Decrement(amount); }

    /**
     * Decrements the value by 1.
     * @return The new value.
     */
    double operator--() noexcept {
        Dec(1);
        return Value();
    }

    double Value() const noexcept;

    bool operator==(const Gauge& rhs) const noexcept { return &handle == &rhs.handle; }
    bool operator!=(const Gauge& rhs) const noexcept { return &handle != &rhs.handle; }

    bool CompareLabels(const prometheus::Labels& lbls) const { return labels == lbls; }

private:
    Handle& handle;
    prometheus::Labels labels;
    bool has_callback = false;
};

class GaugeFamily : public MetricFamily, public std::enable_shared_from_this<GaugeFamily> {
public:
    static inline const char* OpaqueName = "GaugeMetricFamilyVal";

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    std::shared_ptr<Gauge> GetOrAdd(Span<const LabelView> labels, prometheus::CollectCallbackPtr callback = nullptr);

    /**
     * @copydoc GetOrAdd
     */
    std::shared_ptr<Gauge> GetOrAdd(std::initializer_list<LabelView> labels,
                                    prometheus::CollectCallbackPtr callback = nullptr);

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::GAUGE; }

    GaugeFamily(prometheus::Family<prometheus::Gauge>* family, Span<const std::string_view> labels)
        : MetricFamily(labels), family(family) {}

private:
    prometheus::Family<prometheus::Gauge>* family;
    std::vector<std::shared_ptr<Gauge>> gauges;
};

} // namespace zeek::telemetry
