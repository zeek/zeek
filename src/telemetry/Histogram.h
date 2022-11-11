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

class DblHistogramFamily;
class IntHistogramFamily;
class Manager;

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram
	{
public:
	friend class IntHistogramFamily;

	static inline const char* OpaqueName = "IntHistogramMetricVal";

	IntHistogram() = delete;
	IntHistogram(const IntHistogram&) noexcept = default;
	IntHistogram& operator=(const IntHistogram&) noexcept = default;

	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(int64_t value) noexcept { return broker::telemetry::observe(hdl, value); }

	/// @return The sum of all observed values.
	int64_t Sum() const noexcept { return broker::telemetry::sum(hdl); }

	/// @return The number of buckets, including the implicit "infinite" bucket.
	size_t NumBuckets() const noexcept { return broker::telemetry::num_buckets(hdl); }

	/// @return The number of observations in the bucket at @p index.
	/// @pre index < NumBuckets()
	int64_t CountAt(size_t index) const noexcept { return broker::telemetry::count_at(hdl, index); }

	/// @return The upper bound of the bucket at @p index.
	/// @pre index < NumBuckets()
	int64_t UpperBoundAt(size_t index) const noexcept
		{
		return broker::telemetry::upper_bound_at(hdl, index);
		}

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	constexpr bool IsSameAs(const IntHistogram& other) const noexcept { return hdl == other.hdl; }

private:
	using Handle = broker::telemetry::int_histogram_hdl*;

	explicit IntHistogram(Handle hdl) noexcept : hdl(hdl) { }

	Handle hdl;
	};

/**
 * Checks whether two @ref IntHistogram handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 */
constexpr bool operator==(const IntHistogram& lhs, const IntHistogram& rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates IntHistogram
constexpr bool operator!=(const IntHistogram& lhs, const IntHistogram& rhs) noexcept
	{
	return ! (lhs == rhs);
	}

/**
 * Manages a collection of IntHistogram metrics.
 */
class IntHistogramFamily : public MetricFamily
	{
public:
	friend class Manager;

	static inline const char* OpaqueName = "IntHistogramMetricFamilyVal";

	using InstanceType = IntHistogram;

	IntHistogramFamily(const IntHistogramFamily&) noexcept = default;
	IntHistogramFamily& operator=(const IntHistogramFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntHistogram GetOrAdd(Span<const LabelView> labels)
		{
		return IntHistogram{int_histogram_get_or_add(hdl, labels)};
		}

	/**
	 * @copydoc GetOrAdd
	 */
	IntHistogram GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	using Handle = broker::telemetry::int_histogram_family_hdl*;

	explicit IntHistogramFamily(Handle hdl) : MetricFamily(upcast(hdl)) { }
	};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with floating point precision. Sorts individual measurements
 * into configurable buckets.
 */
class DblHistogram
	{
public:
	friend class DblHistogramFamily;

	static inline const char* OpaqueName = "DblHistogramMetricVal";

	DblHistogram() = delete;
	DblHistogram(const DblHistogram&) noexcept = default;
	DblHistogram& operator=(const DblHistogram&) noexcept = default;

	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(double value) noexcept { broker::telemetry::observe(hdl, value); }

	/// @return The sum of all observed values.
	double Sum() const noexcept { return broker::telemetry::sum(hdl); }

	/// @return The number of buckets, including the implicit "infinite" bucket.
	size_t NumBuckets() const noexcept { return broker::telemetry::num_buckets(hdl); }

	/// @return The number of observations in the bucket at @p index.
	/// @pre index < NumBuckets()
	int64_t CountAt(size_t index) const noexcept { return broker::telemetry::count_at(hdl, index); }

	/// @return The upper bound of the bucket at @p index.
	/// @pre index < NumBuckets()
	double UpperBoundAt(size_t index) const noexcept
		{
		return broker::telemetry::upper_bound_at(hdl, index);
		}

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	constexpr bool IsSameAs(const DblHistogram& other) const noexcept { return hdl == other.hdl; }

private:
	using Handle = broker::telemetry::dbl_histogram_hdl*;

	explicit DblHistogram(Handle hdl) noexcept : hdl(hdl) { }

	Handle hdl;
	};

/**
 * Checks whether two @ref DblHistogram handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 */
constexpr bool operator==(const DblHistogram& lhs, const DblHistogram& rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates DblHistogram
constexpr bool operator!=(const DblHistogram& lhs, const DblHistogram& rhs) noexcept
	{
	return ! (lhs == rhs);
	}

/**
 * Manages a collection of DblHistogram metrics.
 */
class DblHistogramFamily : public MetricFamily
	{
public:
	friend class Manager;

	static inline const char* OpaqueName = "DblHistogramMetricFamilyVal";

	using InstanceType = DblHistogram;

	DblHistogramFamily(const DblHistogramFamily&) noexcept = default;
	DblHistogramFamily& operator=(const DblHistogramFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblHistogram GetOrAdd(Span<const LabelView> labels)
		{
		return DblHistogram{dbl_histogram_get_or_add(hdl, labels)};
		}

	/**
	 * @copydoc GetOrAdd
	 */
	DblHistogram GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	using Handle = broker::telemetry::dbl_histogram_family_hdl*;

	explicit DblHistogramFamily(Handle hdl) : MetricFamily(upcast(hdl)) { }
	};

namespace detail
	{

template <class T> struct HistogramOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Histogram<T> only supports int64_t and double");

	using type = IntHistogram;
	};

template <> struct HistogramOracle<double>
	{
	using type = DblHistogram;
	};

	} // namespace detail

template <class T> using Histogram = typename detail::HistogramOracle<T>::type;

	} // namespace zeek::telemetry
