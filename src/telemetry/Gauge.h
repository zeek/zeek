// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

#include "broker/telemetry/fwd.hh"

namespace zeek::telemetry
	{

class DblGaugeFamily;
class IntGaugeFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge
	{
public:
	friend class IntGaugeFamily;

	static inline const char* OpaqueName = "IntGaugeMetricVal";

	IntGauge() = delete;
	IntGauge(const IntGauge&) noexcept = default;
	IntGauge& operator=(const IntGauge&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { broker::telemetry::inc(hdl); }

	/**
	 * Increments the value by @p amount.
	 */
	void Inc(int64_t amount) noexcept { broker::telemetry::inc(hdl, amount); }

	/**
	 * Increments the value by 1.
	 * @return The new value.
	 */
	int64_t operator++() noexcept { return broker::telemetry::inc(hdl); }

	/**
	 * Decrements the value by 1.
	 */
	void Dec() noexcept { broker::telemetry::dec(hdl); }

	/**
	 * Decrements the value by @p amount.
	 */
	void Dec(int64_t amount) noexcept { broker::telemetry::dec(hdl, amount); }

	/**
	 * Decrements the value by 1.
	 * @return The new value.
	 */
	int64_t operator--() noexcept { return broker::telemetry::dec(hdl); }

	/**
	 * @return The current value.
	 */
	int64_t Value() const noexcept { return broker::telemetry::value(hdl); }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(const IntGauge& other) const noexcept { return hdl == other.hdl; }

private:
	using Handle = broker::telemetry::int_gauge_hdl*;

	explicit IntGauge(Handle hdl) noexcept : hdl(hdl) { }

	Handle hdl;
	};

/**
 * Checks whether two @ref IntGauge handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(const IntGauge& lhs, const IntGauge& rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates IntGauge
constexpr bool operator!=(const IntGauge& lhs, const IntGauge& rhs) noexcept
	{
	return ! (lhs == rhs);
	}

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily : public MetricFamily
	{
public:
	friend class Manager;

	static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

	using InstanceType = IntGauge;

	IntGaugeFamily(const IntGaugeFamily&) noexcept = default;
	IntGaugeFamily& operator=(const IntGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntGauge GetOrAdd(Span<const LabelView> labels)
		{
		return IntGauge{int_gauge_get_or_add(hdl, labels)};
		}

	/**
	 * @copydoc GetOrAdd
	 */
	IntGauge GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	using Handle = broker::telemetry::int_gauge_family_hdl*;

	explicit IntGaugeFamily(Handle hdl) : MetricFamily(upcast(hdl)) { }
	};

/**
 * A handle to a metric that represents a floating point value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class DblGauge
	{
public:
	friend class DblGaugeFamily;

	static inline const char* OpaqueName = "DblGaugeMetricVal";

	DblGauge() = delete;
	DblGauge(const DblGauge&) noexcept = default;
	DblGauge& operator=(const DblGauge&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { broker::telemetry::inc(hdl); }

	/**
	 * Increments the value by @p amount.
	 */
	void Inc(double amount) noexcept { broker::telemetry::inc(hdl, amount); }

	/**
	 * Increments the value by 1.
	 */
	void Dec() noexcept { broker::telemetry::dec(hdl); }

	/**
	 * Increments the value by @p amount.
	 */
	void Dec(double amount) noexcept { broker::telemetry::dec(hdl, amount); }

	/**
	 * @return The current value.
	 */
	double Value() const noexcept { return broker::telemetry::value(hdl); }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(const DblGauge& other) const noexcept { return hdl == other.hdl; }

private:
	using Handle = broker::telemetry::dbl_gauge_hdl*;

	explicit DblGauge(Handle hdl) noexcept : hdl(hdl) { }

	Handle hdl;
	};

/**
 * Checks whether two @ref DblGauge handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(const DblGauge& lhs, const DblGauge& rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates DblGauge
constexpr bool operator!=(const DblGauge& lhs, const DblGauge& rhs) noexcept
	{
	return ! (lhs == rhs);
	}

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily : public MetricFamily
	{
public:
	friend class Manager;

	static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

	using InstanceType = DblGauge;

	DblGaugeFamily(const DblGaugeFamily&) noexcept = default;
	DblGaugeFamily& operator=(const DblGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblGauge GetOrAdd(Span<const LabelView> labels)
		{
		return DblGauge{dbl_gauge_get_or_add(hdl, labels)};
		}

	/**
	 * @copydoc GetOrAdd
	 */
	DblGauge GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	using Handle = broker::telemetry::dbl_gauge_family_hdl*;

	explicit DblGaugeFamily(Handle hdl) : MetricFamily(upcast(hdl)) { }
	};

namespace detail
	{

template <class T> struct GaugeOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Gauge<T> only supports int64_t and double");

	using type = IntGauge;
	};

template <> struct GaugeOracle<double>
	{
	using type = DblGauge;
	};

	} // namespace detail

template <class T> using Gauge = typename detail::GaugeOracle<T>::type;

	} // namespace zeek::telemetry
