// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Histogram.h"

#include <algorithm>

using namespace zeek::telemetry;

double Histogram::Sum() const noexcept {
    auto metric = handle.Collect();
    return static_cast<double>(metric.histogram.sample_sum);
}

Histogram::Histogram(FamilyType* family, const prometheus::Labels& labels,
                     prometheus::Histogram::BucketBoundaries bounds) noexcept
    : handle(family->Add(labels, std::move(bounds))), labels(labels) {}

std::shared_ptr<Histogram> HistogramFamily::GetOrAdd(Span<const LabelView> labels) {
    prometheus::Labels p_labels = detail::BuildPrometheusLabels(labels);

    auto check = [&](const std::shared_ptr<Histogram>& histo) { return histo->CompareLabels(p_labels); };

    if ( auto it = std::find_if(histograms.begin(), histograms.end(), check); it != histograms.end() )
        return *it;

    auto histogram = std::make_shared<Histogram>(family, p_labels, boundaries);
    histograms.push_back(histogram);
    return histogram;
}

/**
 * @copydoc GetOrAdd
 */
std::shared_ptr<Histogram> HistogramFamily::GetOrAdd(std::initializer_list<LabelView> labels) {
    return GetOrAdd(Span{labels.begin(), labels.size()});
}

HistogramFamily::HistogramFamily(prometheus::Family<prometheus::Histogram>* family, Span<const double> bounds,
                                 Span<const std::string_view> labels)
    : MetricFamily(labels), family(family) {
    std::copy(bounds.begin(), bounds.end(), std::back_inserter(boundaries));
}
