// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Gauge.h"

#include <algorithm>

using namespace zeek::telemetry;

double Gauge::Value() const noexcept {
    if ( callback )
        return callback();

    return handle.Value();
}


Gauge::Gauge(FamilyType* family, const prometheus::Labels& labels, detail::CollectCallbackPtr callback) noexcept
    : family(family), handle(family->Add(labels)), labels(labels), callback(std::move(callback)) {}

std::shared_ptr<Gauge> GaugeFamily::GetOrAdd(Span<const LabelView> labels, detail::CollectCallbackPtr callback) {
    prometheus::Labels p_labels = detail::BuildPrometheusLabels(labels);

    auto check = [&](const std::shared_ptr<Gauge>& gauge) { return gauge->CompareLabels(p_labels); };

    if ( auto it = std::ranges::find_if(gauges, check); it != gauges.end() )
        return *it;

    auto gauge = std::make_shared<Gauge>(family, p_labels, callback);
    gauges.push_back(gauge);
    return gauge;
}

std::shared_ptr<Gauge> GaugeFamily::GetOrAdd(std::initializer_list<LabelView> labels,
                                             detail::CollectCallbackPtr callback) {
    return GetOrAdd(Span{labels.begin(), labels.size()}, std::move(callback));
}

void GaugeFamily::RunCallbacks() {
    for ( const auto& g : gauges ) {
        if ( g->HasCallback() )
            g->Set(g->RunCallback());
    }
}
