#include "zeek/telemetry/Gauge.h"

using namespace zeek::telemetry;

double Gauge::Value() const noexcept {
    if ( has_callback ) {
        // Use Collect() here instead of Value() to correctly handle metrics
        // with callbacks.
        auto metric = handle.Collect();
        return metric.gauge.value;
    }

    return handle.Value();
}


Gauge::Gauge(FamilyType* family, const prometheus::Labels& labels, prometheus::CollectCallbackPtr callback) noexcept
    : family(family), handle(family->Add(labels)), labels(labels) {
    if ( callback ) {
        handle.AddCollectCallback(std::move(callback));
        has_callback = true;
    }
}

std::shared_ptr<Gauge> GaugeFamily::GetOrAdd(Span<const LabelView> labels, prometheus::CollectCallbackPtr callback) {
    prometheus::Labels p_labels = detail::BuildPrometheusLabels(labels);

    auto check = [&](const std::shared_ptr<Gauge>& gauge) { return gauge->CompareLabels(p_labels); };

    if ( auto it = std::find_if(gauges.begin(), gauges.end(), check); it != gauges.end() )
        return *it;

    auto gauge = std::make_shared<Gauge>(family, p_labels, callback);
    gauges.push_back(gauge);
    return gauge;
}

std::shared_ptr<Gauge> GaugeFamily::GetOrAdd(std::initializer_list<LabelView> labels,
                                             prometheus::CollectCallbackPtr callback) {
    return GetOrAdd(Span{labels.begin(), labels.size()}, std::move(callback));
}
