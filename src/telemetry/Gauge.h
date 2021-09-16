// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

namespace zeek::telemetry
	{

class DblGaugeFamily;
class IntGaugeFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value. Gauges are less
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge
	{
public:
	friend class IntGaugeFamily;

	struct Impl;

	static inline const char* OpaqueName = "IntGaugeMetricVal";

	IntGauge() = delete;
	IntGauge(const IntGauge&) noexcept = default;
	IntGauge& operator=(const IntGauge&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 */
	void Inc(int64_t amount) noexcept;

	/**
	 * Increments the value by 1.
	 * @return The new value.
	 */
	int64_t operator++() noexcept;

	/**
	 * Decrements the value by 1.
	 */
	void Dec() noexcept;

	/**
	 * Decrements the value by @p amount.
	 */
	void Dec(int64_t amount) noexcept;

	/**
	 * Decrements the value by 1.
	 * @return The new value.
	 */
	int64_t operator--() noexcept;

	/**
	 * @return The current value.
	 */
	int64_t Value() const noexcept;

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(IntGauge other) const noexcept { return pimpl == other.pimpl; }

private:
	explicit IntGauge(Impl* ptr) noexcept : pimpl(ptr) { }

	Impl* pimpl;
	};

/**
 * Checks whether two @ref IntGauge handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(IntGauge lhs, IntGauge rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates IntGauge
constexpr bool operator!=(IntGauge lhs, IntGauge rhs) noexcept
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

	class Impl;

	static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

	using InstanceType = IntGauge;

	IntGaugeFamily(const IntGaugeFamily&) noexcept = default;
	IntGaugeFamily& operator=(const IntGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntGauge GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	IntGauge GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit IntGaugeFamily(Impl* ptr);
	};

/**
 * A handle to a metric that represents a floating point value. Gauges are less
 * permissive than counters and also allow decrementing the value.
 * up.
 */
class DblGauge
	{
public:
	friend class DblGaugeFamily;

	struct Impl;

	static inline const char* OpaqueName = "DblGaugeMetricVal";

	DblGauge() = delete;
	DblGauge(const DblGauge&) noexcept = default;
	DblGauge& operator=(const DblGauge&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 */
	void Inc(double amount) noexcept;

	/**
	 * Increments the value by 1.
	 */
	void Dec() noexcept;

	/**
	 * Increments the value by @p amount.
	 */
	void Dec(double amount) noexcept;

	/**
	 * @return The current value.
	 */
	double Value() const noexcept;

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(DblGauge other) const noexcept { return pimpl == other.pimpl; }

private:
	explicit DblGauge(Impl* ptr) noexcept : pimpl(ptr) { }

	Impl* pimpl;
	};

/**
 * Checks whether two @ref DblGauge handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(DblGauge lhs, DblGauge rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates DblGauge
constexpr bool operator!=(DblGauge lhs, DblGauge rhs) noexcept
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

	class Impl;

	static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

	using InstanceType = DblGauge;

	DblGaugeFamily(const DblGaugeFamily&) noexcept = default;
	DblGaugeFamily& operator=(const DblGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblGauge GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	DblGauge GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit DblGaugeFamily(Impl* ptr);
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
