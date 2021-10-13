// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

namespace zeek::telemetry
	{

class DblCounterFamily;
class IntCounterFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter
	{
public:
	friend class IntCounterFamily;

	struct Impl;

	static inline const char* OpaqueName = "IntCounterMetricVal";

	IntCounter() = delete;
	IntCounter(const IntCounter&) noexcept = default;
	IntCounter& operator=(const IntCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void Inc(int64_t amount) noexcept;

	/**
	 * Increments the value by 1.
	 * @return The new value.
	 */
	int64_t operator++() noexcept;

	/**
	 * @return The current value.
	 */
	int64_t Value() const noexcept;

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(IntCounter other) const noexcept { return pimpl == other.pimpl; }

private:
	explicit IntCounter(Impl* ptr) noexcept : pimpl(ptr) { }

	Impl* pimpl;
	};

/**
 * Checks whether two @ref IntCounter handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(IntCounter lhs, IntCounter rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates IntCounter
constexpr bool operator!=(IntCounter lhs, IntCounter rhs) noexcept
	{
	return ! (lhs == rhs);
	}

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public MetricFamily
	{
public:
	friend class Manager;

	class Impl;

	static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

	using InstanceType = IntCounter;

	IntCounterFamily(const IntCounterFamily&) noexcept = default;
	IntCounterFamily& operator=(const IntCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntCounter GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	IntCounter GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit IntCounterFamily(Impl* ptr);
	};

/**
 * A handle to a metric that represents a floating point value that can only go
 * up.
 */
class DblCounter
	{
public:
	friend class DblCounterFamily;

	struct Impl;

	static inline const char* OpaqueName = "DblCounterMetricVal";

	DblCounter() = delete;
	DblCounter(const DblCounter&) noexcept = default;
	DblCounter& operator=(const DblCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void Inc(double amount) noexcept;

	/**
	 * @return The current value.
	 */
	double Value() const noexcept;

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(DblCounter other) const noexcept { return pimpl == other.pimpl; }

private:
	explicit DblCounter(Impl* ptr) noexcept : pimpl(ptr) { }

	Impl* pimpl;
	};

/**
 * Checks whether two @ref DblCounter handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(DblCounter lhs, DblCounter rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates DblCounter
constexpr bool operator!=(DblCounter lhs, DblCounter rhs) noexcept
	{
	return ! (lhs == rhs);
	}

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public MetricFamily
	{
public:
	friend class Manager;

	class Impl;

	static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

	using InstanceType = DblCounter;

	DblCounterFamily(const DblCounterFamily&) noexcept = default;
	DblCounterFamily& operator=(const DblCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblCounter GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	DblCounter GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit DblCounterFamily(Impl* ptr);
	};

namespace detail
	{

template <class T> struct CounterOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Counter<T> only supports int64_t and double");

	using type = IntCounter;
	};

template <> struct CounterOracle<double>
	{
	using type = DblCounter;
	};

	} // namespace detail

template <class T> using Counter = typename detail::CounterOracle<T>::type;

	} // namespace zeek::telemetry
