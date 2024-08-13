#include "zeek/telemetry/Counter.h"

using namespace zeek::telemetry;

Counter::Counter(FamilyType* family, const prometheus::Labels& labels, prometheus::CollectCallbackPtr callback) noexcept
    : family(family), handle(family->Add(labels)), labels(labels) {
    if ( callback ) {
        handle.AddCollectCallback(std::move(callback));
        has_callback = true;
    }
}

double Counter::Value() const noexcept {
    if ( has_callback ) {
        // Use Collect() here instead of Value() to correctly handle metrics with
        // callbacks.
        auto metric = handle.Collect();
        return metric.counter.value;
    }

    return handle.Value();
}

std::shared_ptr<Counter> CounterFamily::GetOrAdd(Span<const LabelView> labels,
                                                 prometheus::CollectCallbackPtr callback) {
    prometheus::Labels p_labels = detail::BuildPrometheusLabels(labels);

    auto check = [&](const std::shared_ptr<Counter>& counter) { return counter->CompareLabels(p_labels); };

    if ( auto it = std::find_if(counters.begin(), counters.end(), check); it != counters.end() )
        return *it;

    auto counter = std::make_shared<Counter>(family, p_labels, callback);
    counters.push_back(counter);
    return counter;
}

std::shared_ptr<Counter> CounterFamily::GetOrAdd(std::initializer_list<LabelView> labels,
                                                 prometheus::CollectCallbackPtr callback) {
    return GetOrAdd(Span{labels.begin(), labels.size()}, std::move(callback));
}
