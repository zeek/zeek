// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <prometheus/family.h>
#include <prometheus/labels.h>
#include <span>
#include <string_view>

namespace zeek::telemetry {

using LabelView = std::pair<std::string_view, std::string_view>;

namespace detail {

/**
 * Builds a set of labels for prometheus based on a set of labels from
 * Zeek. This adds an 'endpoint' label if it's missing from the set.
 */
prometheus::Labels BuildPrometheusLabels(std::span<const LabelView> labels);

/**
 * Builds a full metric name for Prometheus from prefix, name, and unit values.
 */
std::string BuildFullPrometheusName(std::string_view prefix, std::string_view name, std::string_view unit,
                                    bool is_sum = false);

} // namespace detail
} // namespace zeek::telemetry
