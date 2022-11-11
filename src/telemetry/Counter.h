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

	static inline const char* OpaqueName = "IntCounterMetricVal";

	IntCounter() = delete;
	IntCounter(const IntCounter&) noexcept = default;
	IntCounter& operator=(const IntCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { broker::telemetry::inc(hdl); }

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void Inc(int64_t amount) noexcept { broker::telemetry::inc(hdl, amount); }

	/**
	 * Increments the value by 1.
	 * @return The new value.
	 */
	int64_t operator++() noexcept { return broker::telemetry::inc(hdl); }

	/**
	 * @return The current value.
	 */
	int64_t Value() const noexcept { return broker::telemetry::value(hdl); }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(const IntCounter& other) const noexcept { return hdl == other.hdl; }

private:
	using Handle = broker::telemetry::int_counter_hdl*;

	explicit IntCounter(Handle hdl) noexcept : hdl(hdl) { }

	Handle hdl;
	};

/**
 * Checks whether two @ref IntCounter handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(const IntCounter& lhs, const IntCounter& rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates IntCounter
constexpr bool operator!=(const IntCounter& lhs, const IntCounter& rhs) noexcept
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

	static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

	using InstanceType = IntCounter;

	IntCounterFamily(const IntCounterFamily&) noexcept = default;
	IntCounterFamily& operator=(const IntCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntCounter GetOrAdd(Span<const LabelView> labels)
		{
		return IntCounter{int_counter_get_or_add(hdl, labels)};
		}

	/**
	 * @copydoc GetOrAdd
	 */
	IntCounter GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	using Handle = broker::telemetry::int_counter_family_hdl*;

	explicit IntCounterFamily(Handle hdl) : MetricFamily(upcast(hdl)) { }
	};

/**
 * A handle to a metric that represents a floating point value that can only go
 * up.
 */
class DblCounter
	{
public:
	friend class DblCounterFamily;

	static inline const char* OpaqueName = "DblCounterMetricVal";

	DblCounter() = delete;
	DblCounter(const DblCounter&) noexcept = default;
	DblCounter& operator=(const DblCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { broker::telemetry::inc(hdl); }

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void Inc(double amount) noexcept { broker::telemetry::inc(hdl, amount); }

	/**
	 * @return The current value.
	 */
	double Value() const noexcept { return broker::telemetry::value(hdl); }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	constexpr bool IsSameAs(const DblCounter& other) const noexcept { return hdl == other.hdl; }

private:
	using Handle = broker::telemetry::dbl_counter_hdl*;

	explicit DblCounter(Handle hdl) noexcept : hdl(hdl) { }

	Handle hdl;
	};

/**
 * Checks whether two @ref DblCounter handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 * @note compare their @c value instead to check for equality.
 */
constexpr bool operator==(const DblCounter& lhs, const DblCounter& rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates DblCounter
constexpr bool operator!=(const DblCounter& lhs, const DblCounter& rhs) noexcept
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

	static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

	using InstanceType = DblCounter;

	DblCounterFamily(const DblCounterFamily&) noexcept = default;
	DblCounterFamily& operator=(const DblCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblCounter GetOrAdd(Span<const LabelView> labels)
		{
		return DblCounter{dbl_counter_get_or_add(hdl, labels)};
		}

	/**
	 * @copydoc GetOrAdd
	 */
	DblCounter GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	using Handle = broker::telemetry::dbl_counter_family_hdl*;

	explicit DblCounterFamily(Handle hdl) : MetricFamily(upcast(hdl)) { }
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
