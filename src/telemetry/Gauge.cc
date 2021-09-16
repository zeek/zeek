// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Gauge.h"

#include "zeek/telemetry/Detail.h"

#include "caf/telemetry/gauge.hpp"
#include "caf/telemetry/metric_family.hpp"
#include "caf/telemetry/metric_family_impl.hpp"

namespace zeek::telemetry
	{

// -- IntGauge ---------------------------------------------------------------

void IntGauge::Inc() noexcept
	{
	deref(pimpl).inc();
	}

void IntGauge::Inc(int64_t amount) noexcept
	{
	deref(pimpl).inc(amount);
	}

void IntGauge::Dec() noexcept
	{
	deref(pimpl).dec();
	}

void IntGauge::Dec(int64_t amount) noexcept
	{
	deref(pimpl).dec(amount);
	}

int64_t IntGauge::operator++() noexcept
	{
	return ++deref(pimpl);
	}

int64_t IntGauge::operator--() noexcept
	{
	return --deref(pimpl);
	}

int64_t IntGauge::Value() const noexcept
	{
	return deref(pimpl).value();
	}

IntGaugeFamily::IntGaugeFamily(Impl* ptr) : MetricFamily(upcast(ptr)) { }

IntGauge IntGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels,
	                          [this](auto nativeLabels)
	                          {
								  auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
								  return IntGauge{hdl};
							  });
	}

// -- DblGauge ---------------------------------------------------------------

void DblGauge::Inc() noexcept
	{
	deref(pimpl).inc();
	}

void DblGauge::Inc(double amount) noexcept
	{
	deref(pimpl).inc(amount);
	}

void DblGauge::Dec() noexcept
	{
	deref(pimpl).dec();
	}

void DblGauge::Dec(double amount) noexcept
	{
	deref(pimpl).dec(amount);
	}

double DblGauge::Value() const noexcept
	{
	return deref(pimpl).value();
	}

DblGaugeFamily::DblGaugeFamily(Impl* ptr) : MetricFamily(upcast(ptr)) { }

DblGauge DblGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels,
	                          [this](auto nativeLabels)
	                          {
								  auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
								  return DblGauge{hdl};
							  });
	}

	} // namespace zeek::telemetry
