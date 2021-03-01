// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

namespace zeek::telemetry {

class DblCounterFamily;
class IntCounterFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter {
public:
	friend class IntCounterFamily;

	struct Impl;

	IntCounter() = delete;
	IntCounter(const IntCounter&) noexcept = default;
	IntCounter& operator=(const IntCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void inc(int64_t amount) noexcept;

	/**
	 * Increments the value by 1.
	 * @returns the new value.
	 */
	int64_t operator++() noexcept;

	/**
	 * @returns the current value.
	 */
	int64_t value() const noexcept;

	/**
	 * @returns whether @c this and @p other refer to the same counter.
	 */
	constexpr bool isSameAs(IntCounter other) const noexcept
		{
		return pimpl == other.pimpl;
		}

private:
	explicit IntCounter(Impl* ptr) noexcept : pimpl(ptr)
		{
		}

	Impl* pimpl;
};

/**
 * Checks whether two @ref IntCounter handles are identical.
 * @returns whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(IntCounter lhs, IntCounter rhs) noexcept
	{
	return lhs.isSameAs(rhs);
	}

/// @relates IntCounter
constexpr bool operator!=(IntCounter lhs, IntCounter rhs) noexcept
	{
	return !(lhs == rhs);
	}

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public MetricFamily {
public:
	friend class Manager;

	class Impl;

	IntCounterFamily(const IntCounterFamily&) noexcept = default;
	IntCounterFamily& operator=(const IntCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntCounter getOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc getOrAdd
	 */
	IntCounter getOrAdd(std::initializer_list<LabelView> labels)
		{
		return getOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit IntCounterFamily(Impl* ptr);
};

/**
 * A handle to a metric that represents a floating point value that can only go
 * up.
 */
class DblCounter {
public:
	friend class DblCounterFamily;

	struct Impl;

	DblCounter() = delete;
	DblCounter(const DblCounter&) noexcept = default;
	DblCounter& operator=(const DblCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void inc(double amount) noexcept;

	/**
	 * @returns the current value.
	 */
	double value() const noexcept;

	/**
	 * @returns whether @c this and @p other refer to the same counter.
	 */
	constexpr bool isSameAs(DblCounter other) const noexcept
		{
		return pimpl == other.pimpl;
		}

private:
	explicit DblCounter(Impl* ptr) noexcept : pimpl(ptr)
		{
		}

	Impl* pimpl;
};

/**
 * Checks whether two @ref DblCounter handles are identical.
 * @returns whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(DblCounter lhs, DblCounter rhs) noexcept
	{
	return lhs.isSameAs(rhs);
	}

/// @relates DblCounter
constexpr bool operator!=(DblCounter lhs, DblCounter rhs) noexcept
	{
	return !(lhs == rhs);
	}

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public MetricFamily {
public:
	friend class Manager;

	class Impl;

	DblCounterFamily(const DblCounterFamily&) noexcept = default;
	DblCounterFamily& operator=(const DblCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblCounter getOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc getOrAdd
	 */
	DblCounter getOrAdd(std::initializer_list<LabelView> labels)
		{
		return getOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit DblCounterFamily(Impl* ptr);
};

namespace detail {

template <class T>
struct CounterOracle {
	static_assert(std::is_same<T, int64_t>::value,
	              "Counter<T> only supports int64_t and double");

	using type = IntCounter;

	using family_type = IntCounterFamily;
};

template <>
struct CounterOracle<double> {
	using type = DblCounter;

	using family_type = DblCounterFamily;
};

} // namespace detail

template <class T>
using Counter = typename detail::CounterOracle<T>::type;

template <class T>
using CounterFamily = typename detail::CounterOracle<T>::family_type;

} // namespace zeek::telemetry
