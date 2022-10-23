// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Span.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"
#include "zeek/telemetry/Histogram.h"

#include "broker/telemetry/fwd.hh"

namespace broker
	{
class endpoint;
	}

namespace zeek
	{
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;
	}

namespace zeek::Broker
	{
class Manager;
	}

namespace zeek::telemetry
	{

/**
 * Manages a collection of metric families.
 */
class Manager
	{
public:
	friend class Broker::Manager;

	Manager();

	Manager(const Manager&) = delete;

	Manager& operator=(const Manager&) = delete;

	virtual ~Manager();

	/**
	 * Initialization of the manager. This is called late during Zeek's
	 * initialization after any scripts are processed.
	 */
	virtual void InitPostScript();

	/**
	 * Supported metric types.
	 */
	enum class MetricType
		{
		Counter,
		Gauge,
		Histogram
		};

	/**
	 * Captures information about counter and gauge metrics.
	 */
	struct CollectedValueMetric
		{
		/**
		 * Constructor.
		 * @param metric_type The type of this metric.
		 * @param family Broker layer family handle for this metric.
		 * @param label_values The string values for each of the metric's labels.
		 * @param value The metric's current value.
		 */
		CollectedValueMetric(MetricType metric_type,
		                     const broker::telemetry::metric_family_hdl* family,
		                     std::vector<std::string_view> label_values,
		                     std::variant<double, int64_t> value)
			: metric_type(metric_type), family(family), label_values(std::move(label_values)),
			  value(value)
			{
			}

		/**
		 * @return A script layer Telemetry::Metric record for this metric.
		 */
		zeek::RecordValPtr AsMetricRecord() const;

		enum MetricType metric_type;
		const broker::telemetry::metric_family_hdl* family;
		std::vector<std::string_view> label_values;
		std::variant<double, int64_t> value;
		};

	/**
	 * Captures information about histogram metrics.
	 */
	struct CollectedHistogramMetric
		{
		/**
		 * Helper struct representing a single bucket of a histogram.
		 * @tparam T The data type used by the histogram (double or int64_t).
		 */
		template <class T> struct Bucket
			{
			Bucket(T count, T upper_bound) : count(count), upper_bound(upper_bound) { }

			T count;
			T upper_bound;
			};

		/**
		 * Helper struct representing a histogram as sum and buckets.
		 * @tparam T The data type used by the histogram (double or int64_t).
		 */
		template <class T> struct HistogramData
			{
			T sum;
			std::vector<Bucket<T>> buckets;
			};

		using DblHistogramData = HistogramData<double>;
		using IntHistogramData = HistogramData<int64_t>;

		/**
		 * Constructor.
		 * @param family Broker layer family handle for this metric.
		 * @param label_values The string values for each of the metric's labels.
		 * @param histogram The histogram's data (sum and individual buckets).
		 */
		CollectedHistogramMetric(const broker::telemetry::metric_family_hdl* family,
		                         std::vector<std::string_view> label_values,
		                         std::variant<DblHistogramData, IntHistogramData> histogram)

			: family(family), label_values(std::move(label_values)), histogram(std::move(histogram))
			{
			}

		const broker::telemetry::metric_family_hdl* family;
		std::vector<std::string_view> label_values;
		std::variant<DblHistogramData, IntHistogramData> histogram;

		/**
		 * @return A script layer Telemetry::HistogramMetric record for this histogram.
		 */
		zeek::RecordValPtr AsHistogramMetricRecord() const;
		};

	/**
	 * @return A script layer Telemetry::MetricOpts record for the given metric family.
	 * @param metric_typ The type of metric.
	 * @param family Broker layer family handle for the family.
	 * @tparam T The underlying data type (double or int64_t)
	 */
	template <typename T>
	zeek::RecordValPtr GetMetricOptsRecord(MetricType metric_type,
	                                       const broker::telemetry::metric_family_hdl* family);

	/**
	 * @return All counter and gauge metrics and their values matching prefix and name.
	 * @param prefix The prefix pattern to use for filtering. Supports globbing.
	 * @param name The name pattern to use for filtering. Supports globbing.
	 */
	std::vector<CollectedValueMetric> CollectMetrics(std::string_view prefix,
	                                                 std::string_view name);

	/**
	 * @return All histogram metrics and their data matching prefix and name.
	 * @param prefix The prefix pattern to use for filtering. Supports globbing.
	 * @param name The name pattern to use for filtering. Supports globbing.
	 */
	std::vector<CollectedHistogramMetric> CollectHistogramMetrics(std::string_view prefix,
	                                                              std::string_view name);

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
	                   Span<const std::string_view> labels, std::string_view helptext,
	                   std::string_view unit = "1", bool is_sum = false)
		{
		if constexpr ( std::is_same<ValueType, int64_t>::value )
			{
			auto fam = int_counter_fam(Ptr(), prefix, name, labels, helptext, unit, is_sum);
			return IntCounterFamily{fam};
			}
		else
			{
			static_assert(std::is_same<ValueType, double>::value,
			              "metrics only support int64_t and double values");
			auto fam = dbl_counter_fam(Ptr(), prefix, name, labels, helptext, unit, is_sum);
			return DblCounterFamily{fam};
			}
		}

	/// @copydoc CounterFamily
	template <class ValueType = int64_t>
	auto CounterFamily(std::string_view prefix, std::string_view name,
	                   std::initializer_list<std::string_view> labels, std::string_view helptext,
	                   std::string_view unit = "1", bool is_sum = false)
		{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return CounterFamily<ValueType>(prefix, name, lbl_span, helptext, unit, is_sum);
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
	Counter<ValueType> CounterInstance(std::string_view prefix, std::string_view name,
	                                   Span<const LabelView> labels, std::string_view helptext,
	                                   std::string_view unit = "1", bool is_sum = false)
		{
		return WithLabelNames(labels,
		                      [&, this](auto labelNames)
		                      {
								  auto family = CounterFamily<ValueType>(prefix, name, labelNames,
			                                                             helptext, unit, is_sum);
								  return family.getOrAdd(labels);
							  });
		}

	/// @copydoc counterInstance
	template <class ValueType = int64_t>
	Counter<ValueType> CounterInstance(std::string_view prefix, std::string_view name,
	                                   std::initializer_list<LabelView> labels,
	                                   std::string_view helptext, std::string_view unit = "1",
	                                   bool is_sum = false)
		{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return CounterInstance(prefix, name, lbl_span, helptext, unit, is_sum);
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
	                 Span<const std::string_view> labels, std::string_view helptext,
	                 std::string_view unit = "1", bool is_sum = false)
		{
		if constexpr ( std::is_same<ValueType, int64_t>::value )
			{
			auto fam = int_gauge_fam(Ptr(), prefix, name, labels, helptext, unit, is_sum);
			return IntGaugeFamily{fam};
			}
		else
			{
			static_assert(std::is_same<ValueType, double>::value,
			              "metrics only support int64_t and double values");
			auto fam = dbl_gauge_fam(Ptr(), prefix, name, labels, helptext, unit, is_sum);
			return DblGaugeFamily{fam};
			}
		}

	/// @copydoc GaugeFamily
	template <class ValueType = int64_t>
	auto GaugeFamily(std::string_view prefix, std::string_view name,
	                 std::initializer_list<std::string_view> labels, std::string_view helptext,
	                 std::string_view unit = "1", bool is_sum = false)
		{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return GaugeFamily<ValueType>(prefix, name, lbl_span, helptext, unit, is_sum);
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
	Gauge<ValueType> GaugeInstance(std::string_view prefix, std::string_view name,
	                               Span<const LabelView> labels, std::string_view helptext,
	                               std::string_view unit = "1", bool is_sum = false)
		{
		return WithLabelNames(labels,
		                      [&, this](auto labelNames)
		                      {
								  auto family = GaugeFamily<ValueType>(prefix, name, labelNames,
			                                                           helptext, unit, is_sum);
								  return family.getOrAdd(labels);
							  });
		}

	/// @copydoc GaugeInstance
	template <class ValueType = int64_t>
	Gauge<ValueType> GaugeInstance(std::string_view prefix, std::string_view name,
	                               std::initializer_list<LabelView> labels,
	                               std::string_view helptext, std::string_view unit = "1",
	                               bool is_sum = false)
		{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return GaugeInstance(prefix, name, lbl_span, helptext, unit, is_sum);
		}

	// Forces the compiler to use the type `Span<const T>` instead of trying to
	// match parameters to a `span`.
	template <class T> struct ConstSpanOracle
		{
		using Type = Span<const T>;
		};

	// Convenience alias to safe some typing.
	template <class T> using ConstSpan = typename ConstSpanOracle<T>::Type;

	/**
	 * Returns a histogram metric family. Creates the family lazily if
	 * necessary.
	 * @param prefix The prefix (namespace) this family belongs to. Usually the
	 *               application or protocol name, e.g., `http`. The prefix `caf`
	 *               as well as prefixes starting with an underscore are
	 *               reserved.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Names for all label dimensions of the metric.
	 * @param default_upper_bounds Upper bounds for the metric buckets.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement. Please use base units such as `bytes` or
	 *             `seconds` (prefer lowercase). The pseudo-unit `1` identifies
	 *             dimensionless counts.
	 * @param is_sum Setting this to `true` indicates that this metric adds
	 *               something up to a total, where only the total value is of
	 *               interest. For example, the total number of HTTP requests.
	 * @note The first call wins when calling this function multiple times with
	 *       different bucket settings. Users may also override
	 *       @p default_upper_bounds via run-time configuration.
	 */
	template <class ValueType = int64_t>
	auto HistogramFamily(std::string_view prefix, std::string_view name,
	                     Span<const std::string_view> labels,
	                     ConstSpan<ValueType> default_upper_bounds, std::string_view helptext,
	                     std::string_view unit = "1", bool is_sum = false)
		{
		if constexpr ( std::is_same<ValueType, int64_t>::value )
			{
			auto fam = int_histogram_fam(Ptr(), prefix, name, labels, default_upper_bounds,
			                             helptext, unit, is_sum);
			return IntHistogramFamily{fam};
			}
		else
			{
			static_assert(std::is_same<ValueType, double>::value,
			              "metrics only support int64_t and double values");
			auto fam = dbl_histogram_fam(Ptr(), prefix, name, labels, default_upper_bounds,
			                             helptext, unit, is_sum);
			return DblHistogramFamily{fam};
			}
		}

	/// @copydoc HistogramFamily
	template <class ValueType = int64_t>
	auto HistogramFamily(std::string_view prefix, std::string_view name,
	                     std::initializer_list<std::string_view> labels,
	                     ConstSpan<ValueType> default_upper_bounds, std::string_view helptext,
	                     std::string_view unit = "1", bool is_sum = false)
		{
		auto lbl_span = Span{labels.begin(), labels.size()};
		return HistogramFamily<ValueType>(prefix, name, lbl_span, default_upper_bounds, helptext,
		                                  unit, is_sum);
		}

	/**
	 * Returns a histogram. Creates the family lazily if necessary.
	 * @param prefix The prefix (namespace) this family belongs to. Usually the
	 *               application or protocol name, e.g., `http`. The prefix `caf`
	 *               as well as prefixes starting with an underscore are
	 *               reserved.
	 * @param name The human-readable name of the metric, e.g., `requests`.
	 * @param labels Names for all label dimensions of the metric.
	 * @param default_upper_bounds Upper bounds for the metric buckets.
	 * @param helptext Short explanation of the metric.
	 * @param unit Unit of measurement. Please use base units such as `bytes` or
	 *             `seconds` (prefer lowercase). The pseudo-unit `1` identifies
	 *             dimensionless counts.
	 * @param is_sum Setting this to `true` indicates that this metric adds
	 *               something up to a total, where only the total value is of
	 *               interest. For example, the total number of HTTP requests.
	 * @note The first call wins when calling this function multiple times with
	 *       different bucket settings. Users may also override
	 *       @p default_upper_bounds via run-time configuration.
	 */
	template <class ValueType = int64_t>
	Histogram<ValueType>
	HistogramInstance(std::string_view prefix, std::string_view name, Span<const LabelView> labels,
	                  ConstSpan<ValueType> default_upper_bounds, std::string_view helptext,
	                  std::string_view unit = "1", bool is_sum = false)
		{
		return WithLabelNames(labels,
		                      [&, this](auto labelNames)
		                      {
								  auto family = HistogramFamily<ValueType>(prefix, name, labelNames,
			                                                               default_upper_bounds,
			                                                               helptext, unit, is_sum);
								  return family.getOrAdd(labels);
							  });
		}

	/// @copdoc HistogramInstance
	template <class ValueType = int64_t>
	Histogram<ValueType> HistogramInstance(std::string_view prefix, std::string_view name,
	                                       std::initializer_list<LabelView> labels,
	                                       ConstSpan<ValueType> default_upper_bounds,
	                                       std::string_view helptext, std::string_view unit = "1",
	                                       bool is_sum = false)
		{
		auto lbls = Span{labels.begin(), labels.size()};
		return HistogramInstance(prefix, name, lbls, default_upper_bounds, helptext, unit, is_sum);
		}

protected:
	template <class F> static void WithLabelNames(Span<const LabelView> xs, F continuation)
		{
		if ( xs.size() <= 10 )
			{
			std::string_view buf[10];
			for ( size_t index = 0; index < xs.size(); ++index )
				buf[index] = xs[index].first;

			return continuation(Span{buf, xs.size()});
			}
		else
			{
			std::vector<std::string_view> buf;
			for ( auto x : xs )
				buf.emplace_back(x.first, x.second);

			return continuation(Span{buf});
			}
		}

	broker::telemetry::metric_registry_impl* Ptr() { return pimpl.get(); }

	// Connects all the dots after the Broker Manager constructed the endpoint
	// for this Zeek instance. Called from Broker::Manager::InitPostScript().
	void InitPostBrokerSetup(broker::endpoint&);

	IntrusivePtr<broker::telemetry::metric_registry_impl> pimpl;

private:
	// Caching of metric_family_hdl instances to their Zeek record representation.
	std::unordered_map<const broker::telemetry::metric_family_hdl*, zeek::RecordValPtr>
		metric_opts_cache;
	};

	} // namespace zeek::telemetry

namespace zeek
	{

extern telemetry::Manager* telemetry_mgr;

	} // namespace zeek
