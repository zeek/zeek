// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Counter.h"

#include "zeek/telemetry/Detail.h"

#include "caf/telemetry/counter.hpp"
#include "caf/telemetry/metric_family.hpp"
#include "caf/telemetry/metric_family_impl.hpp"

namespace zeek::telemetry
	{

// -- IntCounter ---------------------------------------------------------------

void IntCounter::Inc() noexcept
	{
	deref(pimpl).inc();
	}

void IntCounter::Inc(int64_t amount) noexcept
	{
	deref(pimpl).inc(amount);
	}

int64_t IntCounter::operator++() noexcept
	{
	return ++deref(pimpl);
	}

int64_t IntCounter::Value() const noexcept
	{
	return deref(pimpl).value();
	}

IntCounterFamily::IntCounterFamily(Impl* ptr) : MetricFamily(upcast(ptr)) { }

IntCounter IntCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels,
	                          [this](auto nativeLabels)
	                          {
								  auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
								  return IntCounter{hdl};
							  });
	}

// -- DblCounter ---------------------------------------------------------------

void DblCounter::Inc() noexcept
	{
	deref(pimpl).inc();
	}

void DblCounter::Inc(double amount) noexcept
	{
	deref(pimpl).inc(amount);
	}

double DblCounter::Value() const noexcept
	{
	return deref(pimpl).value();
	}

DblCounterFamily::DblCounterFamily(Impl* ptr) : MetricFamily(upcast(ptr)) { }

DblCounter DblCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels,
	                          [this](auto nativeLabels)
	                          {
								  auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
								  return DblCounter{hdl};
							  });
	}

	} // namespace zeek::telemetry
