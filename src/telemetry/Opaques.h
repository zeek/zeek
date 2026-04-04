// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <prometheus/counter.h>
#include <prometheus/family.h>

#include "zeek/OpaqueVal.h"
#include "zeek/broker/Data.h"

namespace zeek {

namespace telemetry {

class Counter;
class CounterFamily;
class Gauge;
class GaugeFamily;
class Histogram;
class HistogramFamily;

} // namespace telemetry

/**
 * Base class for metric handles. Handle types are not serializable.
 */
class TelemetryVal : public OpaqueVal {
protected:
    explicit TelemetryVal(const std::shared_ptr<telemetry::Counter>&);
    explicit TelemetryVal(const std::shared_ptr<telemetry::CounterFamily>&);
    explicit TelemetryVal(const std::shared_ptr<telemetry::Gauge>&);
    explicit TelemetryVal(const std::shared_ptr<telemetry::GaugeFamily>&);
    explicit TelemetryVal(const std::shared_ptr<telemetry::Histogram>&);
    explicit TelemetryVal(const std::shared_ptr<telemetry::HistogramFamily>&);

    std::optional<BrokerData> DoSerializeData() const override { return std::nullopt; }
    bool DoUnserializeData(BrokerDataView data) override { return false; }
};

template<class Handle>
class TelemetryValImpl : public TelemetryVal {
public:
    using HandleType = std::shared_ptr<Handle>;

    explicit TelemetryValImpl(HandleType hdl) : TelemetryVal(hdl), hdl(std::move(hdl)) {}

    HandleType GetHandle() const noexcept { return hdl; }

    static zeek::OpaqueValPtr OpaqueInstantiate() {
        reporter->Error("TelemetryValImpl::OpaqueInstantiate is unsupported");
        return nullptr;
    }

protected:
    ValPtr DoClone(CloneState*) override { return make_intrusive<TelemetryValImpl>(hdl); }

    const char* OpaqueName() const override;

private:
    HandleType hdl;
};

using CounterMetricVal = TelemetryValImpl<telemetry::Counter>;
using CounterMetricFamilyVal = TelemetryValImpl<telemetry::CounterFamily>;
using GaugeMetricVal = TelemetryValImpl<telemetry::Gauge>;
using GaugeMetricFamilyVal = TelemetryValImpl<telemetry::GaugeFamily>;
using HistogramMetricVal = TelemetryValImpl<telemetry::Histogram>;
using HistogramMetricFamilyVal = TelemetryValImpl<telemetry::HistogramFamily>;

} // namespace zeek
