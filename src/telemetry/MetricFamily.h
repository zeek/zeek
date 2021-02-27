// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "Span.h"

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
	struct Impl;

	MetricFamily() = delete;
	MetricFamily(const MetricFamily&) noexcept = default;
	MetricFamily& operator=(const MetricFamily&) noexcept = default;

	/**
	 * @returns the prefix (namespace) this family belongs to. Builtin metrics
	 *          of Zeek return @c zeek. Custom metrics, e.g., created in a
	 *          script, may use a prefix that represents the application/script
	 *          or protocol (e.g. @c http) name.
	 */
	std::string_view prefix() const noexcept;

	/**
	 * @returns the human-readable name of the metric, e.g.,
	 *          @p open-connections.
	 */
	std::string_view name() const noexcept;

    /**
     * @returns the names for all label dimensions.
     */
	Span<const std::string> labelNames() const noexcept;

    /**
     * @returns a short explanation of the metric.
     */
	std::string_view helptext() const noexcept;

	/**
	 * @returns the unit of measurement, preferably a base unit such as
	 *          @c bytes or @c seconds. Dimensionless counts return the
	 *          pseudo-unit @c 1.
	 */
	std::string_view unit() const noexcept;

	/**
	 * @returns whether metrics of this family accumulate values, where only the
	 *          total value is of interest. For example, the total number of
	 *          HTTP requests.
	 */
	bool isSum() const noexcept;

protected:
	explicit MetricFamily(Impl* ptr) : pimpl(ptr)
		{
		// nop
		}

	Impl* pimpl;
};

} // namespace zeek::telemetry
