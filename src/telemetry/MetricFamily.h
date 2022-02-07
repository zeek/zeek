// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "zeek/Span.h"

#include "broker/telemetry/metric_family.hh"

namespace zeek::telemetry
	{

/**
 * A key-value pair for a single label dimension.
 */
using LabelView = std::pair<std::string_view, std::string_view>;

/**
 * Manages a collection (family) of metrics. All members of the family share
 * the same prefix (namespace), name, and label dimensions.
 */
class MetricFamily
	{
public:
	MetricFamily() = delete;
	MetricFamily(const MetricFamily&) noexcept = default;
	MetricFamily& operator=(const MetricFamily&) noexcept = default;

	/**
	 * @return The prefix (namespace) this family belongs to. Builtin metrics
	 *         of Zeek return @c zeek. Custom metrics, e.g., created in a
	 *         script, may use a prefix that represents the application/script
	 *         or protocol (e.g. @c http) name.
	 */
	std::string_view Prefix() const noexcept { return broker::telemetry::prefix(hdl); }

	/**
	 * @return The human-readable name of the metric, e.g.,
	 *          @p open-connections.
	 */
	std::string_view Name() const noexcept { return broker::telemetry::name(hdl); }

	/**
	 * @return The names for all label dimensions.
	 */
	Span<const std::string> LabelNames() const noexcept
		{
		return broker::telemetry::label_names(hdl);
		}

	/**
	 * @return A short explanation of the metric.
	 */
	std::string_view Helptext() const noexcept { return broker::telemetry::helptext(hdl); }

	/**
	 * @return The unit of measurement, preferably a base unit such as
	 *         @c bytes or @c seconds. Dimensionless counts return the
	 *         pseudo-unit @c 1.
	 */
	std::string_view Unit() const noexcept { return broker::telemetry::unit(hdl); }

	/**
	 * @return Whether metrics of this family accumulate values, where only the
	 *         total value is of interest. For example, the total number of
	 *         HTTP requests.
	 */
	bool IsSum() const noexcept { return broker::telemetry::is_sum(hdl); }

protected:
	using Handle = broker::telemetry::metric_family_hdl*;

	explicit MetricFamily(Handle hdl) : hdl(hdl) { }

	Handle hdl;
	};

	} // namespace zeek::telemetry
