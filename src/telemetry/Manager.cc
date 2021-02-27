// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#include "caf/telemetry/metric_registry.hpp"

#include "zeek/3rdparty/doctest.h"

namespace zeek::telemetry {

namespace {

namespace ct = caf::telemetry;

using NativeManager = ct::metric_registry;

using NativeIntCounter = ct::int_counter;

using NativeIntCounterFamily = ct::metric_family_impl<NativeIntCounter>;

using NativeDblCounter = ct::dbl_counter;

using NativeDblCounterFamily = ct::metric_family_impl<NativeDblCounter>;

auto& deref(Manager::Impl* ptr)
	{
	return *reinterpret_cast<NativeManager*>(ptr);
	}

auto opaque(NativeManager* ptr)
	{
	return reinterpret_cast<Manager::Impl*>(ptr);
	}

auto opaque(NativeIntCounterFamily* ptr)
	{
	return reinterpret_cast<IntCounterFamily::Impl*>(ptr);
	}

auto opaque(NativeDblCounterFamily* ptr)
	{
	return reinterpret_cast<DblCounterFamily::Impl*>(ptr);
	}

template <class F>
auto withNative(Span<const std::string_view> xs, F continuation)
	{
	if (xs.size() <= 10)
		{
		caf::string_view buf[10];
		for (size_t index = 0; index < xs.size(); ++index)
			buf[index] = xs[index];
		return continuation(Span{buf, xs.size()});
		}
	else
		{
		std::vector<caf::string_view> buf;
		for (auto x : xs)
			buf.emplace_back(x);
		return continuation(Span{buf});
		}
	}

} // namespace

IntCounterFamily Manager::intCounterFam(std::string_view prefix,
                                        std::string_view name,
                                        Span<const std::string_view> labels,
                                        std::string_view helptext,
                                        std::string_view unit, bool isSum)
	{
	return withNative(labels, [&, this](auto xs)
		{
		auto ptr = deref(pimpl).counter_family(prefix, name, xs,
		                                       helptext, unit, isSum);
		return IntCounterFamily{opaque(ptr)};
		});
	}

DblCounterFamily Manager::dblCounterFam(std::string_view prefix,
                                        std::string_view name,
                                        Span<const std::string_view> labels,
                                        std::string_view helptext,
                                        std::string_view unit, bool isSum)
	{
	return withNative(labels, [&, this](auto xs)
		{
		auto ptr = deref(pimpl).counter_family<double>(prefix, name, xs,
		                                               helptext, unit, isSum);
		return DblCounterFamily{opaque(ptr)};
		});
	}

} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace zeek::telemetry;

SCENARIO("telemetry managers provide access to counters")
	{
	GIVEN("a telemetry manager")
		{
		NativeManager nativeMgr;
		Manager mgr{opaque(&nativeMgr)};
		WHEN("retrieving an IntCounter singleton")
			{
			auto first = mgr.counterSingleton("zeek", "int-count", "test");
			THEN("its initial value is zero")
				{
				CHECK_EQ(first.value(), 0);
				}
			AND_THEN("calling inc() or operator++ changes the value")
				{
				first.inc();
				CHECK_EQ(first.value(), 1);
				first.inc(2);
				CHECK_EQ(first.value(), 3);
				CHECK_EQ(++first, 4);
				CHECK_EQ(first.value(), 4);
				}
			AND_THEN("calling counterSingleton again for the same name returns the same handle")
				{
				auto second = mgr.counterSingleton("zeek", "int-count", "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling counterSingleton for a different name returns another handle")
				{
				auto third = mgr.counterSingleton("zeek", "int-count-2", "test");
				CHECK_NE(first, third);
				}
			}
		WHEN("retrieving a DblCounter singleton")
			{
			auto first = mgr.counterSingleton<double>("zeek", "dbl-count", "test");
			THEN("its initial value is zero")
				{
				CHECK_EQ(first.value(), 0.0);
				}
			AND_THEN("calling inc() changes the value")
				{
				first.inc();
				CHECK_EQ(first.value(), 1.0);
				first.inc(3.0);
				CHECK_EQ(first.value(), 4.0);
				}
			AND_THEN("calling counterSingleton again for the same name returns the same handle")
				{
				auto second = mgr.counterSingleton<double>("zeek", "dbl-count", "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling counterSingleton for a different name returns another handle")
				{
				auto third = mgr.counterSingleton<double>("zeek", "dbl-count-2", "test");
				CHECK_NE(first, third);
				}
			}
		}
	}
