// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Histogram.h"

#include <cassert>

#include "zeek/telemetry/Detail.h"

#include "caf/telemetry/histogram.hpp"
#include "caf/telemetry/metric_family.hpp"
#include "caf/telemetry/metric_family_impl.hpp"

namespace zeek::telemetry
	{

// -- IntHistogram ---------------------------------------------------------------

void IntHistogram::Observe(int64_t value) noexcept
	{
	deref(pimpl).observe(value);
	}

int64_t IntHistogram::Sum() const noexcept
	{
	return deref(pimpl).sum();
	}

size_t IntHistogram::NumBuckets() const noexcept
	{
	return deref(pimpl).buckets().size();
	}

int64_t IntHistogram::CountAt(size_t index) const noexcept
	{
	auto xs = deref(pimpl).buckets();
	assert(index < xs.size());
	return xs[index].count.value();
	}

int64_t IntHistogram::UpperBoundAt(size_t index) const noexcept
	{
	auto xs = deref(pimpl).buckets();
	assert(index < xs.size());
	return xs[index].upper_bound;
	}

IntHistogramFamily::IntHistogramFamily(Impl* ptr) : MetricFamily(upcast(ptr)) { }

IntHistogram IntHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels,
	                          [this](auto nativeLabels)
	                          {
								  auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
								  return IntHistogram{hdl};
							  });
	}

// -- DblHistogram ---------------------------------------------------------------

void DblHistogram::Observe(double amount) noexcept
	{
	deref(pimpl).observe(amount);
	}

double DblHistogram::Sum() const noexcept
	{
	return deref(pimpl).sum();
	}

size_t DblHistogram::NumBuckets() const noexcept
	{
	return deref(pimpl).buckets().size();
	}

int64_t DblHistogram::CountAt(size_t index) const noexcept
	{
	auto xs = deref(pimpl).buckets();
	assert(index < xs.size());
	return xs[index].count.value();
	}

double DblHistogram::UpperBoundAt(size_t index) const noexcept
	{
	auto xs = deref(pimpl).buckets();
	assert(index < xs.size());
	return xs[index].upper_bound;
	}

DblHistogramFamily::DblHistogramFamily(Impl* ptr) : MetricFamily(upcast(ptr)) { }

DblHistogram DblHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels,
	                          [this](auto nativeLabels)
	                          {
								  auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
								  return DblHistogram{hdl};
							  });
	}

	} // namespace zeek::telemetry
