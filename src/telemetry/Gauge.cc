// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Gauge.h"

#include "caf/telemetry/gauge.hpp"
#include "caf/telemetry/metric_family.hpp"
#include "caf/telemetry/metric_family_impl.hpp"

namespace zeek::telemetry {

// -- private utilities --------------------------------------------------------

namespace {

namespace ct = caf::telemetry;

using NativeMetricFamily = ct::metric_family;

using NativeIntGauge = ct::int_gauge;

using NativeIntGaugeFamily = ct::metric_family_impl<NativeIntGauge>;

using NativeDblGauge = ct::dbl_gauge;

using NativeDblGaugeFamily = ct::metric_family_impl<NativeDblGauge>;

auto& deref(IntGauge::Impl* ptr)
	{
	return *reinterpret_cast<NativeIntGauge*>(ptr);
	}

auto& deref(IntGaugeFamily*, MetricFamily::Impl* ptr)
	{
	auto basePtr = reinterpret_cast<NativeMetricFamily*>(ptr);
	return *static_cast<NativeIntGaugeFamily*>(basePtr);
	}

auto upcast(IntGaugeFamily::Impl* ptr)
	{
	auto native = reinterpret_cast<NativeIntGaugeFamily*>(ptr);
	auto basePtr = static_cast<NativeMetricFamily*>(native);
	return reinterpret_cast<MetricFamily::Impl*>(basePtr);
	}

auto opaque(NativeIntGauge* ptr)
	{
	return reinterpret_cast<IntGauge::Impl*>(ptr);
	}

auto& deref(DblGauge::Impl* ptr)
	{
	return *reinterpret_cast<ct::dbl_gauge*>(ptr);
	}

auto& deref(DblGaugeFamily*, MetricFamily::Impl* ptr)
	{
	auto basePtr = reinterpret_cast<NativeMetricFamily*>(ptr);
	return *static_cast<NativeDblGaugeFamily*>(basePtr);
	}

auto upcast(DblGaugeFamily::Impl* ptr)
	{
	auto native = reinterpret_cast<NativeDblGaugeFamily*>(ptr);
	auto basePtr = static_cast<NativeMetricFamily*>(native);
	return reinterpret_cast<MetricFamily::Impl*>(basePtr);
	}

auto opaque(NativeDblGauge* ptr)
	{
	return reinterpret_cast<DblGauge::Impl*>(ptr);
	}

template <class F>
auto withNativeLabels(Span<const LabelView> xs, F continuation)
	{
	if (xs.size() <= 10)
		{
		ct::label_view buf[10]={
			{{},{}}, {{},{}}, {{},{}}, {{},{}}, {{},{}},
			{{},{}}, {{},{}}, {{},{}}, {{},{}}, {{},{}},
		};
		for (size_t index = 0; index < xs.size(); ++index)
			buf[index] = ct::label_view{xs[index].first, xs[index].second};
		return continuation(Span{buf, xs.size()});
		}
	else
		{
		std::vector<ct::label_view> buf;
		for (auto x : xs)
			buf.emplace_back(x.first, x.second);
		return continuation(Span{buf});
		}
	}

} // namespace

// -- IntGauge ---------------------------------------------------------------

void IntGauge::inc() noexcept
	{
	deref(pimpl).inc();
	}

void IntGauge::inc(int64_t amount) noexcept
	{
	deref(pimpl).inc(amount);
	}

void IntGauge::dec() noexcept
	{
	deref(pimpl).dec();
	}

void IntGauge::dec(int64_t amount) noexcept
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

int64_t IntGauge::value() const noexcept
	{
	return deref(pimpl).value();
	}

IntGaugeFamily::IntGaugeFamily(Impl* ptr) : MetricFamily(upcast(ptr))
	{
	// nop
	}

IntGauge IntGaugeFamily::getOrAdd(Span<const LabelView> labels)
	{
	return withNativeLabels(labels, [this](auto nativeLabels)
		{
		auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
		return IntGauge{hdl};
		});
	}

// -- DblGauge ---------------------------------------------------------------

void DblGauge::inc() noexcept
	{
	deref(pimpl).inc();
	}

void DblGauge::inc(double amount) noexcept
	{
	deref(pimpl).inc(amount);
	}

void DblGauge::dec() noexcept
	{
	deref(pimpl).dec();
	}

void DblGauge::dec(double amount) noexcept
	{
	deref(pimpl).dec(amount);
	}

double DblGauge::value() const noexcept
	{
	return deref(pimpl).value();
	}

DblGaugeFamily::DblGaugeFamily(Impl* ptr) : MetricFamily(upcast(ptr))
	{
	// nop
	}

DblGauge DblGaugeFamily::getOrAdd(Span<const LabelView> labels)
	{
	return withNativeLabels(labels, [this](auto nativeLabels)
		{
		auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
		return DblGauge{hdl};
		});
	}

} // namespace zeek::telemetry
