// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <vector>

#include "zeek/Span.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"

namespace zeek::telemetry {

/**
 * Manages a collection of metric families.
 */
class Manager {
public:
	class Impl;

	explicit Manager(Impl* ptr) : pimpl(ptr)
	{
	//nop
	}

	Manager(const Manager&) = delete;

	Manager& operator=(const Manager&) = delete;

	/**
	 * @returns a counter metric family. Creates the family lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Names for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param isSum Indicates whether this metric accumulates something, where
	 *              only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	CounterFamily<ValueType>
	counterFamily(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext,
	              std::string_view unit = "1", bool isSum = false) {
		if constexpr (std::is_same<ValueType, int64_t>::value)
			{
			return intCounterFam(prefix, name, labels, helptext, unit, isSum);
			}
		else
			{
			static_assert(std::is_same<ValueType, double>::value,
			              "metrics only support int64_t and double values");
			return dblCounterFam(prefix, name, labels, helptext, unit, isSum);
			}
	}

	/// @copydoc counterFamily
	template <class ValueType = int64_t>
	CounterFamily<ValueType>
	counterFamily(std::string_view prefix, std::string_view name,
	              std::initializer_list<std::string_view> labels,
	              std::string_view helptext, std::string_view unit = "1",
	              bool isSum = false)
	{
		auto lblSpan = Span{labels.begin(), labels.size()};
		return counterFamily<ValueType>(prefix, name, lblSpan, helptext,
		                                unit, isSum);
	}

	/**
	 * Accesses a counter instance. Creates the hosting metric family as well
	 * as the counter lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Values for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param isSum Indicates whether this metric accumulates something, where
	 *              only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Counter<ValueType>
	counterInstance(std::string_view prefix, std::string_view name,
	                Span<const LabelView> labels, std::string_view helptext,
	                std::string_view unit = "1", bool isSum = false)
		{
		return withLabelNames(labels, [&, this](auto labelNames)
			{
			auto family = counterFamily<ValueType>(prefix, name, labelNames,
			                                       helptext, unit, isSum);
			return family.getOrAdd(labels);
			});
		}

	/// @copydoc counterInstance
	template <class ValueType = int64_t>
	Counter<ValueType>
	counterInstance(std::string_view prefix, std::string_view name,
	                std::initializer_list<LabelView> labels,
	                std::string_view helptext, std::string_view unit = "1",
	                bool isSum = false)
		{
		auto lblSpan = Span{labels.begin(), labels.size()};
		return counterInstance(prefix, name, lblSpan, helptext, unit, isSum);
		}

	/**
	 * Accesses a counter singleton, i.e., a counter that belongs to a family
	 * without label dimensions (which thus only has a single member). Creates
	 * the hosting metric family as well as the counter lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param isSum Indicates whether this metric accumulates something, where
	 *              only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Counter<ValueType>
	counterSingleton(std::string_view prefix, std::string_view name,
	                 std::string_view helptext, std::string_view unit = "1",
	                 bool isSum = false)
		{
		auto labels = Span<const std::string_view>{};
		auto fam = counterFamily<ValueType>(prefix, name, labels, helptext,
		                                    unit, isSum);
		return fam.getOrAdd({});
	}

	/**
	 * @returns a gauge metric family. Creates the family lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Names for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param isSum Indicates whether this metric accumulates something, where
	 *              only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	GaugeFamily<ValueType>
	gaugeFamily(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext,
	              std::string_view unit = "1", bool isSum = false) {
		if constexpr (std::is_same<ValueType, int64_t>::value)
			{
			return intGaugeFam(prefix, name, labels, helptext, unit, isSum);
			}
		else
			{
			static_assert(std::is_same<ValueType, double>::value,
			              "metrics only support int64_t and double values");
			return dblGaugeFam(prefix, name, labels, helptext, unit, isSum);
			}
	}

	/// @copydoc gaugeFamily
	template <class ValueType = int64_t>
	GaugeFamily<ValueType>
	gaugeFamily(std::string_view prefix, std::string_view name,
	              std::initializer_list<std::string_view> labels,
	              std::string_view helptext, std::string_view unit = "1",
	              bool isSum = false)
	{
		auto lblSpan = Span{labels.begin(), labels.size()};
		return gaugeFamily<ValueType>(prefix, name, lblSpan, helptext,
		                              unit, isSum);
	}

	/**
	 * Accesses a gauge instance. Creates the hosting metric family as well
	 * as the gauge lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Values for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param isSum Indicates whether this metric accumulates something, where
	 *              only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Gauge<ValueType>
	gaugeInstance(std::string_view prefix, std::string_view name,
	                Span<const LabelView> labels, std::string_view helptext,
	                std::string_view unit = "1", bool isSum = false)
		{
		return withLabelNames(labels, [&, this](auto labelNames)
			{
			auto family = gaugeFamily<ValueType>(prefix, name, labelNames,
			                                     helptext, unit, isSum);
			return family.getOrAdd(labels);
			});
		}

	/// @copydoc gaugeInstance
	template <class ValueType = int64_t>
	Gauge<ValueType>
	gaugeInstance(std::string_view prefix, std::string_view name,
	                std::initializer_list<LabelView> labels,
	                std::string_view helptext, std::string_view unit = "1",
	                bool isSum = false)
		{
		auto lblSpan = Span{labels.begin(), labels.size()};
		return gaugeInstance(prefix, name, lblSpan, helptext, unit, isSum);
		}

	/**
	 * Accesses a gauge singleton, i.e., a gauge that belongs to a family
	 * without label dimensions (which thus only has a single member). Creates
	 * the hosting metric family as well as the gauge lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param isSum Indicates whether this metric accumulates something, where
	 *              only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Gauge<ValueType>
	gaugeSingleton(std::string_view prefix, std::string_view name,
	                 std::string_view helptext, std::string_view unit = "1",
	                 bool isSum = false)
		{
		auto labels = Span<const std::string_view>{};
		auto fam = gaugeFamily<ValueType>(prefix, name, labels, helptext,
		                                  unit, isSum);
		return fam.getOrAdd({});
	}

private:
	IntCounterFamily
	intCounterFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit, bool isSum);

	DblCounterFamily
	dblCounterFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit, bool isSum);

	IntGaugeFamily
	intGaugeFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit, bool isSum);

	DblGaugeFamily
	dblGaugeFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit, bool isSum);

	template <class F>
	static void withLabelNames(Span<const LabelView> xs, F continuation)
		{
		if (xs.size() <= 10) {
			std::string_view buf[10];
			for (size_t index = 0; index < xs.size(); ++index)
				buf[index] = xs[index].first;
			return continuation(Span{buf, xs.size()});
		} else {
			std::vector<std::string_view> buf;
			for (auto x : xs)
				buf.emplace_back(x.first, x.second);
			return continuation(Span{buf});
		}
		}

	Impl* pimpl;
};

} // namespace zeek::telemetry

namespace zeek {

extern telemetry::Manager* telemetry_mgr;

} // namespace zeek
