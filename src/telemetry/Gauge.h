// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

namespace zeek::telemetry {

class DblGaugeFamily;
class IntGaugeFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value. Gauges are less
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge {
public:
	friend class IntGaugeFamily;

	struct Impl;

	IntGauge() = delete;
	IntGauge(const IntGauge&) noexcept = default;
	IntGauge& operator=(const IntGauge&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 */
	void inc(int64_t amount) noexcept;

	/**
	 * Increments the value by 1.
	 * @returns the new value.
	 */
	int64_t operator++() noexcept;

	/**
	 * Decrements the value by 1.
	 */
	void dec() noexcept;

	/**
	 * Decrements the value by @p amount.
	 */
	void dec(int64_t amount) noexcept;

	/**
	 * Decrements the value by 1.
	 * @returns the new value.
	 */
	int64_t operator--() noexcept;

	/**
	 * @returns the current value.
	 */
	int64_t value() const noexcept;

	/**
	 * @returns whether @c this and @p other refer to the same counter.
	 */
	constexpr bool isSameAs(IntGauge other) const noexcept
		{
		return pimpl == other.pimpl;
		}

private:
	explicit IntGauge(Impl* ptr) noexcept : pimpl(ptr)
		{
		}

	Impl* pimpl;
};

/**
 * Checks whether two @ref IntGauge handles are identical.
 * @returns whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(IntGauge lhs, IntGauge rhs) noexcept
	{
	return lhs.isSameAs(rhs);
	}

/// @relates IntGauge
constexpr bool operator!=(IntGauge lhs, IntGauge rhs) noexcept
	{
	return !(lhs == rhs);
	}

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily : public MetricFamily {
public:
	friend class Manager;

	class Impl;

	IntGaugeFamily(const IntGaugeFamily&) noexcept = default;
	IntGaugeFamily& operator=(const IntGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntGauge getOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc getOrAdd
	 */
	IntGauge getOrAdd(std::initializer_list<LabelView> labels)
		{
		return getOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit IntGaugeFamily(Impl* ptr);
};

/**
 * A handle to a metric that represents a floating point value. Gauges are less
 * permissive than counters and also allow decrementing the value.
 * up.
 */
class DblGauge {
public:
	friend class DblGaugeFamily;

	struct Impl;

	DblGauge() = delete;
	DblGauge(const DblGauge&) noexcept = default;
	DblGauge& operator=(const DblGauge&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 */
	void inc(double amount) noexcept;

	/**
	 * Increments the value by 1.
	 */
	void dec() noexcept;

	/**
	 * Increments the value by @p amount.
	 */
	void dec(double amount) noexcept;

	/**
	 * @returns the current value.
	 */
	double value() const noexcept;

	/**
	 * @returns whether @c this and @p other refer to the same counter.
	 */
	constexpr bool isSameAs(DblGauge other) const noexcept
		{
		return pimpl == other.pimpl;
		}

private:
	explicit DblGauge(Impl* ptr) noexcept : pimpl(ptr)
		{
		}

	Impl* pimpl;
};

/**
 * Checks whether two @ref DblGauge handles are identical.
 * @returns whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(DblGauge lhs, DblGauge rhs) noexcept
	{
	return lhs.isSameAs(rhs);
	}

/// @relates DblGauge
constexpr bool operator!=(DblGauge lhs, DblGauge rhs) noexcept
	{
	return !(lhs == rhs);
	}

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily : public MetricFamily {
public:
	friend class Manager;

	class Impl;

	DblGaugeFamily(const DblGaugeFamily&) noexcept = default;
	DblGaugeFamily& operator=(const DblGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblGauge getOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc getOrAdd
	 */
	DblGauge getOrAdd(std::initializer_list<LabelView> labels)
		{
		return getOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit DblGaugeFamily(Impl* ptr);
};

namespace detail {

template <class T>
struct GaugeOracle {
	static_assert(std::is_same<T, int64_t>::value,
	              "Gauge<T> only supports int64_t and double");

	using type = IntGauge;

	using family_type = IntGaugeFamily;
};

template <>
struct GaugeOracle<double> {
	using type = DblGauge;

	using family_type = DblGaugeFamily;
};

} // namespace detail

template <class T>
using Gauge = typename detail::GaugeOracle<T>::type;

template <class T>
using GaugeFamily = typename detail::GaugeOracle<T>::family_type;

} // namespace zeek::telemetry
