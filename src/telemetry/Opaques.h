// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <prometheus/counter.h>
#include <prometheus/family.h>
#include <zeek/OpaqueVal.h>
#include <zeek/broker/Data.h>

namespace zeek {

/**
 * Base class for metric handles. Handle types are not serializable.
 */
class TelemetryVal : public OpaqueVal {
protected:
    explicit TelemetryVal(std::shared_ptr<telemetry::IntCounter>);
    explicit TelemetryVal(std::shared_ptr<telemetry::IntCounterFamily>);
    explicit TelemetryVal(std::shared_ptr<telemetry::DblCounter>);
    explicit TelemetryVal(std::shared_ptr<telemetry::DblCounterFamily>);
    explicit TelemetryVal(std::shared_ptr<telemetry::IntGauge>);
    explicit TelemetryVal(std::shared_ptr<telemetry::IntGaugeFamily>);
    explicit TelemetryVal(std::shared_ptr<telemetry::DblGauge>);
    explicit TelemetryVal(std::shared_ptr<telemetry::DblGaugeFamily>);
    explicit TelemetryVal(std::shared_ptr<telemetry::IntHistogram>);
    explicit TelemetryVal(std::shared_ptr<telemetry::IntHistogramFamily>);
    explicit TelemetryVal(std::shared_ptr<telemetry::DblHistogram>);
    explicit TelemetryVal(std::shared_ptr<telemetry::DblHistogramFamily>);

    std::optional<BrokerData> DoSerializeData() const override { return std::nullopt; }
    bool DoUnserializeData(BrokerDataView data) override { return false; }
};

template<class Handle>
class TelemetryValImpl : public TelemetryVal {
public:
    using HandleType = std::shared_ptr<Handle>;

    explicit TelemetryValImpl(HandleType hdl) : TelemetryVal(hdl), hdl(hdl) {}

    HandleType GetHandle() const noexcept { return hdl; }

    static zeek::OpaqueValPtr OpaqueInstantiate() {
        reporter->Error("TelemetryValImpl::OpaqueInstantiate is unsupported");
        return nullptr;
    }

protected:
    ValPtr DoClone(CloneState*) override { return make_intrusive<TelemetryValImpl>(hdl); }

    const char* OpaqueName() const override { return Handle::OpaqueName; }

private:
    HandleType hdl;
};

using IntCounterMetricVal = TelemetryValImpl<telemetry::IntCounter>;
using IntCounterMetricFamilyVal = TelemetryValImpl<telemetry::IntCounterFamily>;
using DblCounterMetricVal = TelemetryValImpl<telemetry::DblCounter>;
using DblCounterMetricFamilyVal = TelemetryValImpl<telemetry::DblCounterFamily>;
using IntGaugeMetricVal = TelemetryValImpl<telemetry::IntGauge>;
using IntGaugeMetricFamilyVal = TelemetryValImpl<telemetry::IntGaugeFamily>;
using DblGaugeMetricVal = TelemetryValImpl<telemetry::DblGauge>;
using DblGaugeMetricFamilyVal = TelemetryValImpl<telemetry::DblGaugeFamily>;
using IntHistogramMetricVal = TelemetryValImpl<telemetry::IntHistogram>;
using IntHistogramMetricFamilyVal = TelemetryValImpl<telemetry::IntHistogramFamily>;
using DblHistogramMetricVal = TelemetryValImpl<telemetry::DblHistogram>;
using DblHistogramMetricFamilyVal = TelemetryValImpl<telemetry::DblHistogramFamily>;

} // namespace zeek
