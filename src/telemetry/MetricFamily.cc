// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/MetricFamily.h"

#include "caf/telemetry/metric_family.hpp"

namespace zeek::telemetry
	{

namespace
	{

namespace ct = caf::telemetry;

using NativeMetricFamily = ct::metric_family;

auto& deref(MetricFamily::Impl* ptr)
	{
	return *reinterpret_cast<NativeMetricFamily*>(ptr);
	}

	} // namespace

std::string_view MetricFamily::Prefix() const noexcept
	{
	return deref(pimpl).prefix();
	}

std::string_view MetricFamily::Name() const noexcept
	{
	return deref(pimpl).name();
	}

Span<const std::string> MetricFamily::LabelNames() const noexcept
	{
	return deref(pimpl).label_names();
	}

std::string_view MetricFamily::Helptext() const noexcept
	{
	return deref(pimpl).helptext();
	}

std::string_view MetricFamily::Unit() const noexcept
	{
	return deref(pimpl).unit();
	}

bool MetricFamily::IsSum() const noexcept
	{
	return deref(pimpl).is_sum();
	}

	} // namespace zeek::telemetry
