// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

namespace zeek::telemetry
	{

class DblHistogramFamily;
class IntHistogramFamily;
class Manager;

/**
 * A handle to a metric that represents an aggregatable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram
	{
public:
	friend class IntHistogramFamily;

	struct Impl;

	static inline const char* OpaqueName = "IntHistogramMetricVal";

	IntHistogram() = delete;
	IntHistogram(const IntHistogram&) noexcept = default;
	IntHistogram& operator=(const IntHistogram&) noexcept = default;

	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(int64_t value) noexcept;

	/// @return The sum of all observed values.
	int64_t Sum() const noexcept;

	/// @return The number of buckets, including the implicit "infinite" bucket.
	size_t NumBuckets() const noexcept;

	/// @return The number of observations in the bucket at @p index.
	/// @pre index < NumBuckets()
	int64_t CountAt(size_t index) const noexcept;

	/// @return The upper bound of the bucket at @p index.
	/// @pre index < NumBuckets()
	int64_t UpperBoundAt(size_t index) const noexcept;

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	constexpr bool IsSameAs(IntHistogram other) const noexcept { return pimpl == other.pimpl; }

private:
	explicit IntHistogram(Impl* ptr) noexcept : pimpl(ptr) { }

	Impl* pimpl;
	};

/**
 * Checks whether two @ref IntHistogram handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 */
constexpr bool operator==(IntHistogram lhs, IntHistogram rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates IntHistogram
constexpr bool operator!=(IntHistogram lhs, IntHistogram rhs) noexcept
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

	class Impl;

	static inline const char* OpaqueName = "IntHistogramMetricFamilyVal";

	using InstanceType = IntHistogram;

	IntHistogramFamily(const IntHistogramFamily&) noexcept = default;
	IntHistogramFamily& operator=(const IntHistogramFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	IntHistogram GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	IntHistogram GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit IntHistogramFamily(Impl* ptr);
	};

/**
 * A handle to a metric that represents an aggregatable distribution of observed
 * measurements with floating point precision. Sorts individual measurements
 * into configurable buckets.
 */
class DblHistogram
	{
public:
	friend class DblHistogramFamily;

	struct Impl;

	static inline const char* OpaqueName = "DblHistogramMetricVal";

	DblHistogram() = delete;
	DblHistogram(const DblHistogram&) noexcept = default;
	DblHistogram& operator=(const DblHistogram&) noexcept = default;

	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(double value) noexcept;

	/// @return The sum of all observed values.
	double Sum() const noexcept;

	/// @return The number of buckets, including the implicit "infinite" bucket.
	size_t NumBuckets() const noexcept;

	/// @return The number of observations in the bucket at @p index.
	/// @pre index < NumBuckets()
	int64_t CountAt(size_t index) const noexcept;

	/// @return The upper bound of the bucket at @p index.
	/// @pre index < NumBuckets()
	double UpperBoundAt(size_t index) const noexcept;

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	constexpr bool IsSameAs(DblHistogram other) const noexcept { return pimpl == other.pimpl; }

private:
	explicit DblHistogram(Impl* ptr) noexcept : pimpl(ptr) { }

	Impl* pimpl;
	};

/**
 * Checks whether two @ref DblHistogram handles are identical.
 * @return Whether @p lhs and @p rhs refer to the same object.
 */
constexpr bool operator==(DblHistogram lhs, DblHistogram rhs) noexcept
	{
	return lhs.IsSameAs(rhs);
	}

/// @relates DblHistogram
constexpr bool operator!=(DblHistogram lhs, DblHistogram rhs) noexcept
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

	class Impl;

	static inline const char* OpaqueName = "DblHistogramMetricFamilyVal";

	using InstanceType = DblHistogram;

	DblHistogramFamily(const DblHistogramFamily&) noexcept = default;
	DblHistogramFamily& operator=(const DblHistogramFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	DblHistogram GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	DblHistogram GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	explicit DblHistogramFamily(Impl* ptr);
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
