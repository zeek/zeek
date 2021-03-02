// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Counter.h"

#include "caf/telemetry/counter.hpp"
#include "caf/telemetry/metric_family.hpp"
#include "caf/telemetry/metric_family_impl.hpp"

namespace zeek::telemetry {

// -- private utilities --------------------------------------------------------

namespace {

namespace ct = caf::telemetry;

using NativeMetricFamily = ct::metric_family;

using NativeIntCounter = ct::int_counter;

using NativeIntCounterFamily = ct::metric_family_impl<NativeIntCounter>;

using NativeDblCounter = ct::dbl_counter;

using NativeDblCounterFamily = ct::metric_family_impl<NativeDblCounter>;

auto& deref(IntCounter::Impl* ptr)
	{
	return *reinterpret_cast<NativeIntCounter*>(ptr);
	}

auto& deref(IntCounterFamily*, MetricFamily::Impl* ptr)
	{
	auto basePtr = reinterpret_cast<NativeMetricFamily*>(ptr);
	return *static_cast<NativeIntCounterFamily*>(basePtr);
	}

auto upcast(IntCounterFamily::Impl* ptr)
	{
	auto native = reinterpret_cast<NativeIntCounterFamily*>(ptr);
	auto basePtr = static_cast<NativeMetricFamily*>(native);
	return reinterpret_cast<MetricFamily::Impl*>(basePtr);
	}

auto opaque(NativeIntCounter* ptr)
	{
	return reinterpret_cast<IntCounter::Impl*>(ptr);
	}

auto& deref(DblCounter::Impl* ptr)
	{
	return *reinterpret_cast<ct::dbl_counter*>(ptr);
	}

auto& deref(DblCounterFamily*, MetricFamily::Impl* ptr)
	{
	auto basePtr = reinterpret_cast<NativeMetricFamily*>(ptr);
	return *static_cast<NativeDblCounterFamily*>(basePtr);
	}

auto upcast(DblCounterFamily::Impl* ptr)
	{
	auto native = reinterpret_cast<NativeDblCounterFamily*>(ptr);
	auto basePtr = static_cast<NativeMetricFamily*>(native);
	return reinterpret_cast<MetricFamily::Impl*>(basePtr);
	}

auto opaque(NativeDblCounter* ptr)
	{
	return reinterpret_cast<DblCounter::Impl*>(ptr);
	}

template <class F>
auto withNativeLabels(Span<const LabelView> xs, F continuation)
	{
	if ( xs.size() <= 10 )
		{
		ct::label_view buf[10]={
			{{},{}}, {{},{}}, {{},{}}, {{},{}}, {{},{}},
			{{},{}}, {{},{}}, {{},{}}, {{},{}}, {{},{}},
		};
		for ( size_t index = 0; index < xs.size(); ++index )
			buf[index] = ct::label_view{xs[index].first, xs[index].second};
		return continuation(Span{buf, xs.size()});
		}
	else
		{
		std::vector<ct::label_view> buf;
		for ( auto x : xs )
			buf.emplace_back(x.first, x.second);
		return continuation(Span{buf});
		}
	}

} // namespace

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

IntCounterFamily::IntCounterFamily(Impl* ptr) : MetricFamily(upcast(ptr))
	{
	}

IntCounter IntCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return withNativeLabels(labels, [this](auto nativeLabels)
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

DblCounterFamily::DblCounterFamily(Impl* ptr) : MetricFamily(upcast(ptr))
	{
	}

DblCounter DblCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return withNativeLabels(labels, [this](auto nativeLabels)
		{
		auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
		return DblCounter{hdl};
		});
	}

} // namespace zeek::telemetry
