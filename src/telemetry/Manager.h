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
	}

	Manager(const Manager&) = delete;

	Manager& operator=(const Manager&) = delete;

	virtual ~Manager();

	/**
	 * @return A counter metric family. Creates the family lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Names for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param is_sum Indicates whether this metric accumulates something, where
	 *               only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	auto CounterFamily(std::string_view prefix, std::string_view name,
	                   Span<const std::string_view> labels,
	                   std::string_view helptext,
	                   std::string_view unit = "1", bool is_sum = false) {
		if constexpr (std::is_same<ValueType, int64_t>::value)
			{
			return IntCounterFam(prefix, name, labels, helptext, unit, is_sum);
			}
		else
			{
			static_assert(std::is_same<ValueType, double>::value,
			              "metrics only support int64_t and double values");
			return DblCounterFam(prefix, name, labels, helptext, unit, is_sum);
			}
	}

	/// @copydoc CounterFamily
	template <class ValueType = int64_t>
	auto CounterFamily(std::string_view prefix, std::string_view name,
	                   std::initializer_list<std::string_view> labels,
	                   std::string_view helptext, std::string_view unit = "1",
	                   bool is_sum = false)
	{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return CounterFamily<ValueType>(prefix, name, lbl_span, helptext,
		                                unit, is_sum);
	}

	/**
	 * Accesses a counter instance. Creates the hosting metric family as well
	 * as the counter lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Values for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param is_sum Indicates whether this metric accumulates something, where
	 *               only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Counter<ValueType>
	CounterInstance(std::string_view prefix, std::string_view name,
	                Span<const LabelView> labels, std::string_view helptext,
	                std::string_view unit = "1", bool is_sum = false)
		{
		return WithLabelNames(labels, [&, this](auto labelNames)
			{
			auto family = CounterFamily<ValueType>(prefix, name, labelNames,
			                                       helptext, unit, is_sum);
			return family.getOrAdd(labels);
			});
		}

	/// @copydoc counterInstance
	template <class ValueType = int64_t>
	Counter<ValueType>
	CounterInstance(std::string_view prefix, std::string_view name,
	                std::initializer_list<LabelView> labels,
	                std::string_view helptext, std::string_view unit = "1",
	                bool is_sum = false)
		{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return CounterInstance(prefix, name, lbl_span, helptext, unit, is_sum);
		}

	/**
	 * Accesses a counter singleton, i.e., a counter that belongs to a family
	 * without label dimensions (which thus only has a single member). Creates
	 * the hosting metric family as well as the counter lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param is_sum Indicates whether this metric accumulates something, where
	 *               only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Counter<ValueType>
	CounterSingleton(std::string_view prefix, std::string_view name,
	                 std::string_view helptext, std::string_view unit = "1",
	                 bool is_sum = false)
		{
		auto labels = Span<const std::string_view>{};
		auto fam = CounterFamily<ValueType>(prefix, name, labels, helptext,
		                                    unit, is_sum);
		return fam.GetOrAdd({});
	}

	/**
	 * @return A gauge metric family. Creates the family lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Names for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param is_sum Indicates whether this metric accumulates something, where
	 *               only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	auto GaugeFamily(std::string_view prefix, std::string_view name,
	                 Span<const std::string_view> labels,
	                 std::string_view helptext,
	                 std::string_view unit = "1", bool is_sum = false) {
		if constexpr (std::is_same<ValueType, int64_t>::value)
			{
			return IntGaugeFam(prefix, name, labels, helptext, unit, is_sum);
			}
		else
			{
			static_assert(std::is_same<ValueType, double>::value,
			              "metrics only support int64_t and double values");
			return DblGaugeFam(prefix, name, labels, helptext, unit, is_sum);
			}
	}

	/// @copydoc GaugeFamily
	template <class ValueType = int64_t>
	auto GaugeFamily(std::string_view prefix, std::string_view name,
	                 std::initializer_list<std::string_view> labels,
	                 std::string_view helptext, std::string_view unit = "1",
	                 bool is_sum = false)
	{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return GaugeFamily<ValueType>(prefix, name, lbl_span, helptext,
		                              unit, is_sum);
	}

	/**
	 * Accesses a gauge instance. Creates the hosting metric family as well
	 * as the gauge lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Values for all label dimensions of the metric.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param is_sum Indicates whether this metric accumulates something, where
	 *               only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Gauge<ValueType>
	GaugeInstance(std::string_view prefix, std::string_view name,
	              Span<const LabelView> labels, std::string_view helptext,
	              std::string_view unit = "1", bool is_sum = false)
		{
		return WithLabelNames(labels, [&, this](auto labelNames)
			{
			auto family = GaugeFamily<ValueType>(prefix, name, labelNames,
			                                     helptext, unit, is_sum);
			return family.getOrAdd(labels);
			});
		}

	/// @copydoc GaugeInstance
	template <class ValueType = int64_t>
	Gauge<ValueType>
	GaugeInstance(std::string_view prefix, std::string_view name,
	                std::initializer_list<LabelView> labels,
	                std::string_view helptext, std::string_view unit = "1",
	                bool is_sum = false)
		{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return GaugeInstance(prefix, name, lbl_span, helptext, unit, is_sum);
		}

	/**
	 * Accesses a gauge singleton, i.e., a gauge that belongs to a family
	 * without label dimensions (which thus only has a single member). Creates
	 * the hosting metric family as well as the gauge lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement.
	 * @param is_sum Indicates whether this metric accumulates something, where
	 *               only the total value is of interest.
	 */
	template <class ValueType = int64_t>
	Gauge<ValueType>
	GaugeSingleton(std::string_view prefix, std::string_view name,
	               std::string_view helptext, std::string_view unit = "1",
	               bool is_sum = false)
		{
		auto labels = Span<const std::string_view>{};
		auto fam = GaugeFamily<ValueType>(prefix, name, labels, helptext,
		                                  unit, is_sum);
		return fam.GetOrAdd({});
	}

private:
	IntCounterFamily
	IntCounterFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit,
	              bool is_sum);

	DblCounterFamily
	DblCounterFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit,
	              bool is_sum);

	IntGaugeFamily
	IntGaugeFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit,
	              bool is_sum);

	DblGaugeFamily
	DblGaugeFam(std::string_view prefix, std::string_view name,
	              Span<const std::string_view> labels,
	              std::string_view helptext, std::string_view unit,
	              bool is_sum);

	template <class F>
	static void WithLabelNames(Span<const LabelView> xs, F continuation)
		{
		if ( xs.size() <= 10 ) {
			std::string_view buf[10];
			for ( size_t index = 0; index < xs.size(); ++index )
				buf[index] = xs[index].first;
			return continuation(Span{buf, xs.size()});
		} else {
			std::vector<std::string_view> buf;
			for ( auto x : xs )
				buf.emplace_back(x.first, x.second);
			return continuation(Span{buf});
		}
		}

	Impl* pimpl;
};

} // namespace zeek::telemetry

namespace zeek {

// @note for technically reasons (CAF dependency), this variable gets
//       initialized in broker/Manager.cc.
extern telemetry::Manager* telemetry_mgr;

} // namespace zeek
