// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "zeek/Span.h"
#include "zeek/Val.h"

#include "prometheus/labels.h"

namespace zeek::telemetry {

/**
 * A key-value pair for a single label dimension.
 */
using LabelView = std::pair<std::string_view, std::string_view>;

/**
 * Manages a collection (family) of metrics. All members of the family share
 * the same prefix (namespace), name, and label dimensions.
 */
class MetricFamily {
public:
    MetricFamily() = delete;
    MetricFamily(const MetricFamily&) noexcept = default;
    MetricFamily& operator=(const MetricFamily&) noexcept = default;

    virtual ~MetricFamily() = default;

    /**
     * @return The prefix (namespace) this family belongs to. Builtin metrics
     *         of Zeek return @c zeek. Custom metrics, e.g., created in a
     *         script, may use a prefix that represents the application/script
     *         or protocol (e.g. @c http) name.
     */
    std::string_view Prefix() const noexcept { return prefix; }

    /**
     * @return The human-readable name of the metric, e.g.,
     *          @p open-connections.
     */
    std::string_view Name() const noexcept { return name; }

    /**
     * @return The complete name for the family including prefix.
     */
    std::string FullName() const noexcept { return full_name; }

    /**
     * @return The names for all label dimensions.
     */
    Span<const std::string> LabelNames() const noexcept { return labels; }

    /**
     * @return A short explanation of the metric.
     */
    std::string_view Helptext() const noexcept { return helptext; }

    /**
     * @return The unit of measurement, preferably a base unit such as @c bytes
     *         or @c seconds.
     */
    std::string_view Unit() const noexcept { return unit; }

    /**
     * @return Whether metrics of this family accumulate values, where only the
     *         total value is of interest. For example, the total number of
     *         HTTP requests.
     */
    bool IsSum() const noexcept { return is_sum; }

    /**
     * Converts the family data into script layer record. This record
     * lazily-allocated and reused for each instrument associated with this
     * family.
     *
     * @return A script layer Telemetry::Metric record for this family.
     */
    RecordValPtr GetMetricOptsRecord() const;

    /**
     * @return The type of this metric, defined as one of the values in the
     * script-layer Telemetry::MetricType enum.
     */
    virtual zeek_int_t MetricType() const noexcept = 0;

    /**
     * @return Whether the prefix and name of this family matches the patterns
     * provided.
     */
    bool Matches(std::string_view prefix_pattern, std::string_view name_pattern) const noexcept;

    virtual std::vector<RecordValPtr> Collect() const = 0;

protected:
    MetricFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> lbls,
                 std::string_view helptext, std::string_view unit, bool is_sum = false);

    /**
     * Builds a set of labels for prometheus based on a set of labels from
     * Zeek. This adds an 'endpoint' label if it's missing from the set.
     */
    static prometheus::Labels BuildPrometheusLabels(Span<const LabelView> labels);

    std::string prefix;
    std::string name;
    std::string full_name;
    std::vector<std::string> labels;
    std::string helptext;
    std::string unit;
    bool is_sum = false;

    mutable RecordValPtr record_val;
};

} // namespace zeek::telemetry
