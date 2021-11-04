// See the file "COPYING" in the main distribution directory for copyright.

// This header contains private implementation details for telemetry classes
// and should not get included outside of .cc files.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"
#include "zeek/telemetry/Histogram.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/telemetry/MetricFamily.h"

#include "caf/telemetry/label_view.hpp"
#include "caf/telemetry/metric_family.hpp"

namespace zeek::telemetry
	{

// -- traits for converting between opaque handles and native pointers ---------

/**
 * This trait must provide the member types @c Native for referring to the CAF
 * type, @c Opaque for referring to the @c Impl type. For instance types such as
 * @c IntCounter, the trait must also provide the member type @c NativeFamily.
 */
template <class T> struct PimplTrait;

template <> struct PimplTrait<IntCounter::Impl>
	{
	using Native = caf::telemetry::int_counter;
	using Oqaque = IntCounter::Impl;
	using NativeFamily = caf::telemetry::metric_family_impl<Native>;
	};

template <> struct PimplTrait<caf::telemetry::int_counter> : PimplTrait<IntCounter::Impl>
	{
	};

template <> struct PimplTrait<IntCounterFamily::Impl>
	{
	using Native = typename PimplTrait<IntCounter::Impl>::NativeFamily;
	using Oqaque = IntCounterFamily::Impl;
	};

template <>
struct PimplTrait<typename PimplTrait<IntCounter::Impl>::NativeFamily>
	: PimplTrait<IntCounterFamily::Impl>
	{
	};

template <> struct PimplTrait<DblCounter::Impl>
	{
	using Native = caf::telemetry::dbl_counter;
	using Oqaque = DblCounter::Impl;
	using NativeFamily = caf::telemetry::metric_family_impl<Native>;
	};

template <> struct PimplTrait<caf::telemetry::dbl_counter> : PimplTrait<DblCounter::Impl>
	{
	};

template <> struct PimplTrait<DblCounterFamily::Impl>
	{
	using Native = typename PimplTrait<DblCounter::Impl>::NativeFamily;
	using Oqaque = DblCounterFamily::Impl;
	};

template <>
struct PimplTrait<typename PimplTrait<DblCounter::Impl>::NativeFamily>
	: PimplTrait<DblCounterFamily::Impl>
	{
	};

template <> struct PimplTrait<IntGauge::Impl>
	{
	using Native = caf::telemetry::int_gauge;
	using Oqaque = IntGauge::Impl;
	using NativeFamily = caf::telemetry::metric_family_impl<Native>;
	};

template <> struct PimplTrait<caf::telemetry::int_gauge> : PimplTrait<IntGauge::Impl>
	{
	};

template <> struct PimplTrait<IntGaugeFamily::Impl>
	{
	using Native = typename PimplTrait<IntGauge::Impl>::NativeFamily;
	using Oqaque = IntGaugeFamily::Impl;
	};

template <>
struct PimplTrait<typename PimplTrait<IntGauge::Impl>::NativeFamily>
	: PimplTrait<IntGaugeFamily::Impl>
	{
	};

template <> struct PimplTrait<DblGauge::Impl>
	{
	using Native = caf::telemetry::dbl_gauge;
	using Oqaque = DblGauge::Impl;
	using NativeFamily = caf::telemetry::metric_family_impl<Native>;
	};

template <> struct PimplTrait<caf::telemetry::dbl_gauge> : PimplTrait<DblGauge::Impl>
	{
	};

template <> struct PimplTrait<DblGaugeFamily::Impl>
	{
	using Native = typename PimplTrait<DblGauge::Impl>::NativeFamily;
	using Oqaque = DblGaugeFamily::Impl;
	};

template <>
struct PimplTrait<typename PimplTrait<DblGauge::Impl>::NativeFamily>
	: PimplTrait<DblGaugeFamily::Impl>
	{
	};

template <> struct PimplTrait<IntHistogram::Impl>
	{
	using Native = caf::telemetry::int_histogram;
	using Oqaque = IntHistogram::Impl;
	using NativeFamily = caf::telemetry::metric_family_impl<Native>;
	};

template <> struct PimplTrait<caf::telemetry::int_histogram> : PimplTrait<IntHistogram::Impl>
	{
	};

template <> struct PimplTrait<IntHistogramFamily::Impl>
	{
	using Native = typename PimplTrait<IntHistogram::Impl>::NativeFamily;
	using Oqaque = IntHistogramFamily::Impl;
	};

template <>
struct PimplTrait<typename PimplTrait<IntHistogram::Impl>::NativeFamily>
	: PimplTrait<IntHistogramFamily::Impl>
	{
	};

template <> struct PimplTrait<DblHistogram::Impl>
	{
	using Native = caf::telemetry::dbl_histogram;
	using Oqaque = DblHistogram::Impl;
	using NativeFamily = caf::telemetry::metric_family_impl<Native>;
	};

template <> struct PimplTrait<caf::telemetry::dbl_histogram> : PimplTrait<DblHistogram::Impl>
	{
	};

template <> struct PimplTrait<DblHistogramFamily::Impl>
	{
	using Native = typename PimplTrait<DblHistogram::Impl>::NativeFamily;
	using Oqaque = DblHistogramFamily::Impl;
	};

template <>
struct PimplTrait<typename PimplTrait<DblHistogram::Impl>::NativeFamily>
	: PimplTrait<DblHistogramFamily::Impl>
	{
	};

template <> struct PimplTrait<Manager::Impl>
	{
	using Native = caf::telemetry::metric_registry;
	using Oqaque = Manager::Impl;
	};

template <>
struct PimplTrait<typename PimplTrait<Manager::Impl>::Native> : PimplTrait<Manager::Impl>
	{
	};

// -- free functions -----------------------------------------------------------

template <class T, class NativeType = typename PimplTrait<T>::Native> auto& deref(T* ptr)
	{
	return *reinterpret_cast<NativeType*>(ptr);
	}

template <class Family> auto& deref(Family*, MetricFamily::Impl* ptr)
	{
	using InstanceType = typename Family::InstanceType;
	using ImplType = typename InstanceType::Impl;
	using NativeType = typename PimplTrait<ImplType>::NativeFamily;
	return *reinterpret_cast<NativeType*>(ptr);
	}

template <class T, class OpaqueType = typename PimplTrait<T>::Oqaque> auto opaque(T* ptr)
	{
	return reinterpret_cast<OpaqueType*>(ptr);
	}

template <class Family> auto opaque(const Family*, MetricFamily::Impl* ptr)
	{
	using InstanceType = typename Family::InstanceType;
	using ImplType = typename InstanceType::Impl;
	using OpaqueType = typename PimplTrait<ImplType>::NativeFamily;
	return reinterpret_cast<OpaqueType*>(ptr);
	}

template <class T, class Native = typename PimplTrait<T>::Native> auto upcast(T* ptr)
	{
	auto native = reinterpret_cast<Native*>(ptr);
	auto base_ptr = static_cast<caf::telemetry::metric_family*>(native);
	return reinterpret_cast<MetricFamily::Impl*>(base_ptr);
	}

template <class F> auto with_native_labels(Span<const LabelView> xs, F continuation)
	{
	namespace ct = caf::telemetry;

	if ( xs.size() <= 10 )
		{
		ct::label_view buf[10] = {
			{{}, {}}, {{}, {}}, {{}, {}}, {{}, {}}, {{}, {}},
			{{}, {}}, {{}, {}}, {{}, {}}, {{}, {}}, {{}, {}},
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

template <class F> auto with_native_labels(Span<const std::string_view> xs, F continuation)
	{
	if ( xs.size() <= 10 )
		{
		caf::string_view buf[10];
		for ( size_t index = 0; index < xs.size(); ++index )
			buf[index] = xs[index];
		return continuation(Span{buf, xs.size()});
		}
	else
		{
		std::vector<caf::string_view> buf;
		for ( auto x : xs )
			buf.emplace_back(x);
		return continuation(Span{buf});
		}
	}

	} // namespace zeek::telemetry
