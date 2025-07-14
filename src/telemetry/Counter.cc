// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Counter.h"

#include <algorithm>

using namespace zeek::telemetry;

Counter::Counter(FamilyType* family, const prometheus::Labels& labels, detail::CollectCallbackPtr callback) noexcept
    : family(family), handle(family->Add(labels)), labels(labels), callback(std::move(callback)) {}

double Counter::Value() const noexcept {
    if ( callback )
        return callback();

    return handle.Value();
}

std::shared_ptr<Counter> CounterFamily::GetOrAdd(Span<const LabelView> labels, detail::CollectCallbackPtr callback) {
    prometheus::Labels p_labels = detail::BuildPrometheusLabels(labels);

    auto check = [&](const std::shared_ptr<Counter>& counter) { return counter->CompareLabels(p_labels); };

    if ( auto it = std::find_if(counters.begin(), counters.end(), check); it != counters.end() )
        return *it;

    auto counter = std::make_shared<Counter>(family, p_labels, callback);
    counters.push_back(counter);
    return counter;
}

std::shared_ptr<Counter> CounterFamily::GetOrAdd(std::initializer_list<LabelView> labels,
                                                 detail::CollectCallbackPtr callback) {
    return GetOrAdd(Span{labels.begin(), labels.size()}, std::move(callback));
}

void CounterFamily::RunCallbacks() {
    for ( auto& c : counters ) {
        if ( c->HasCallback() ) {
            double val = c->RunCallback();
            c->Set(val);
        }
    }
}
