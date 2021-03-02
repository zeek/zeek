// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Gauge.h"

#include "caf/telemetry/gauge.hpp"
#include "caf/telemetry/metric_family.hpp"
#include "caf/telemetry/metric_family_impl.hpp"

#include "zeek/telemetry/Detail.h"

namespace ct = caf::telemetry;

namespace zeek::telemetry {

// -- bindings to private utility functions ------------------------------------

template <>
struct PimplTrait<IntGauge::Impl>
	{
	using Native = ct::int_gauge;
	using Oqaque = IntGauge::Impl;
	using NativeFamily = ct::metric_family_impl<Native>;
	};

template <>
struct PimplTrait<ct::int_gauge> : PimplTrait<IntGauge::Impl> { };

template <>
struct PimplTrait<IntGaugeFamily::Impl>
	{
	using Native = typename PimplTrait<IntGauge::Impl>::NativeFamily;
	using Oqaque = IntGaugeFamily::Impl;
	};

template <>
struct PimplTrait<DblGauge::Impl>
	{
	using Native = ct::dbl_gauge;
	using Oqaque = DblGauge::Impl;
	using NativeFamily = ct::metric_family_impl<Native>;
	};

template <>
struct PimplTrait<ct::dbl_gauge> : PimplTrait<DblGauge::Impl> { };

template <>
struct PimplTrait<DblGaugeFamily::Impl>
	{
	using Native = typename PimplTrait<DblGauge::Impl>::NativeFamily;
	using Oqaque = DblGaugeFamily::Impl;
	};

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

IntGaugeFamily::IntGaugeFamily(Impl* ptr) : MetricFamily(upcast(ptr))
	{
	}

IntGauge IntGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels, [this](auto nativeLabels)
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

DblGaugeFamily::DblGaugeFamily(Impl* ptr) : MetricFamily(upcast(ptr))
	{
	}

DblGauge DblGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return with_native_labels(labels, [this](auto nativeLabels)
		{
		auto hdl = opaque(deref(this, pimpl).get_or_add(nativeLabels));
		return DblGauge{hdl};
		});
	}

} // namespace zeek::telemetry
