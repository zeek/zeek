#pragma once

#include <string_view>

#include "zeek/Span.h"
#include "zeek/Val.h"

#include "prometheus/family.h"
#include "prometheus/labels.h"

namespace zeek::telemetry {

using LabelView = std::pair<std::string_view, std::string_view>;

/**
 * Builds a set of labels for prometheus based on a set of labels from
 * Zeek. This adds an 'endpoint' label if it's missing from the set.
 */
prometheus::Labels BuildPrometheusLabels(Span<const LabelView> labels);

/**
 * Builds a full metric name for Prometheus from prefix, name, and unit values.
 */
std::string BuildFullPrometheusName(std::string_view prefix, std::string_view name, std::string_view unit,
                                    bool is_sum = false);

template<typename T>
RecordValPtr GetMetricOptsRecord(prometheus::Family<T>* family, zeek_int_t metric_type);

} // namespace zeek::telemetry
