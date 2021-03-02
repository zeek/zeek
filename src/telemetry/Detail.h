// See the file "COPYING" in the main distribution directory for copyright.

// This header contains private implementation details for telemetry classes
// and should not get included outside of .cc files.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

#include "caf/telemetry/label_view.hpp"
#include "caf/telemetry/metric_family.hpp"

namespace zeek::telemetry {

/**
 * This trait must provide the member types @c Native for referring to the CAF
 * type, @c Opaque for referring to the @c Impl type. For instance types such as
 * @c IntCounter, the trait must also provide the member type @c NativeFamily.
 */
template <class T>
struct PimplTrait;

template <class T, class NativeType = typename PimplTrait<T>::Native>
auto& deref(T* ptr)
	{
	return *reinterpret_cast<NativeType*>(ptr);
	}

template <class Family>
auto& deref(Family*, MetricFamily::Impl* ptr)
	{
	using InstanceType = typename Family::InstanceType;
	using ImplType = typename InstanceType::Impl;
	using NativeType = typename PimplTrait<ImplType>::NativeFamily;
	return *reinterpret_cast<NativeType*>(ptr);
	}

template <class T, class OpaqueType = typename PimplTrait<T>::Oqaque>
auto opaque(T* ptr)
	{
	return reinterpret_cast<OpaqueType*>(ptr);
	}

template <class Family>
auto opaque(const Family*, MetricFamily::Impl* ptr)
	{
	using InstanceType = typename Family::InstanceType;
	using ImplType = typename InstanceType::Impl;
	using OpaqueType = typename PimplTrait<ImplType>::NativeFamily;
	return reinterpret_cast<OpaqueType*>(ptr);
	}

template <class T, class Native = typename PimplTrait<T>::Native>
auto upcast(T* ptr)
	{
	auto native = reinterpret_cast<Native*>(ptr);
	auto base_ptr = static_cast<caf::telemetry::metric_family*>(native);
	return reinterpret_cast<MetricFamily::Impl*>(base_ptr);
	}

template <class F>
auto with_native_labels(Span<const LabelView> xs, F continuation)
	{
	namespace ct = caf::telemetry;

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

} // namespace zeek::telemetry
