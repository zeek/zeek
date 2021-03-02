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

using NativeIntGauge = ct::int_gauge;

using NativeIntGaugeFamily = ct::metric_family_impl<NativeIntGauge>;

using NativeDblGauge = ct::dbl_gauge;

using NativeDblGaugeFamily = ct::metric_family_impl<NativeDblGauge>;

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

auto opaque(NativeIntGaugeFamily* ptr)
	{
	return reinterpret_cast<IntGaugeFamily::Impl*>(ptr);
	}

auto opaque(NativeDblGaugeFamily* ptr)
	{
	return reinterpret_cast<DblGaugeFamily::Impl*>(ptr);
	}

template <class F>
auto with_native(Span<const std::string_view> xs, F continuation)
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

} // namespace

Manager::~Manager()
	{
	}

IntCounterFamily Manager::IntCounterFam(std::string_view prefix,
                                        std::string_view name,
                                        Span<const std::string_view> labels,
                                        std::string_view helptext,
                                        std::string_view unit, bool is_sum)
	{
	return with_native(labels, [&, this](auto xs)
		{
		auto ptr = deref(pimpl).counter_family(prefix, name, xs,
		                                       helptext, unit, is_sum);
		return IntCounterFamily{opaque(ptr)};
		});
	}

DblCounterFamily Manager::DblCounterFam(std::string_view prefix,
                                        std::string_view name,
                                        Span<const std::string_view> labels,
                                        std::string_view helptext,
                                        std::string_view unit, bool is_sum)
	{
	return with_native(labels, [&, this](auto xs)
		{
		auto ptr = deref(pimpl).counter_family<double>(prefix, name, xs,
		                                               helptext, unit, is_sum);
		return DblCounterFamily{opaque(ptr)};
		});
	}

IntGaugeFamily Manager::IntGaugeFam(std::string_view prefix,
                                    std::string_view name,
                                    Span<const std::string_view> labels,
                                    std::string_view helptext,
                                    std::string_view unit, bool is_sum)
	{
	return with_native(labels, [&, this](auto xs)
		{
		auto ptr = deref(pimpl).gauge_family(prefix, name, xs,
		                                     helptext, unit, is_sum);
		return IntGaugeFamily{opaque(ptr)};
		});
	}

DblGaugeFamily Manager::DblGaugeFam(std::string_view prefix,
                                    std::string_view name,
                                    Span<const std::string_view> labels,
                                    std::string_view helptext,
                                    std::string_view unit, bool is_sum)
	{
	return with_native(labels, [&, this](auto xs)
		{
		auto ptr = deref(pimpl).gauge_family<double>(prefix, name, xs,
		                                             helptext, unit, is_sum);
		return DblGaugeFamily{opaque(ptr)};
		});
	}

} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace std::literals;
using namespace zeek::telemetry;

namespace {

template <class T>
auto toVector(zeek::Span<T> xs)
	{
	std::vector<std::remove_const_t<T>> result;
	for ( auto&& x : xs )
		result.emplace_back(x);
	return result;
	}


} // namespace

SCENARIO("telemetry managers provide access to counter singletons")
	{
	GIVEN("a telemetry manager")
		{
		NativeManager native_mgr;
		Manager mgr{opaque(&native_mgr)};
		WHEN("retrieving an IntCounter singleton")
			{
			auto first = mgr.CounterSingleton("zeek", "int-count", "test");
			THEN("its initial value is zero")
				{
				CHECK_EQ(first.Value(), 0);
				}
			AND_THEN("calling Inc() or operator++ changes the value")
				{
				first.Inc();
				CHECK_EQ(first.Value(), 1);
				first.Inc(2);
				CHECK_EQ(first.Value(), 3);
				CHECK_EQ(++first, 4);
				CHECK_EQ(first.Value(), 4);
				}
			AND_THEN("calling counterSingleton again for the same name returns the same handle")
				{
				auto second = mgr.CounterSingleton("zeek", "int-count", "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling counterSingleton for a different name returns another handle")
				{
				auto third = mgr.CounterSingleton("zeek", "int-count-2", "test");
				CHECK_NE(first, third);
				}
			}
		WHEN("retrieving a DblCounter singleton")
			{
			auto first = mgr.CounterSingleton<double>("zeek", "dbl-count", "test");
			THEN("its initial value is zero")
				{
				CHECK_EQ(first.Value(), 0.0);
				}
			AND_THEN("calling Inc() changes the value")
				{
				first.Inc();
				CHECK_EQ(first.Value(), 1.0);
				first.Inc(3.0);
				CHECK_EQ(first.Value(), 4.0);
				}
			AND_THEN("calling counterSingleton again for the same name returns the same handle")
				{
				auto second = mgr.CounterSingleton<double>("zeek", "dbl-count", "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling counterSingleton for a different name returns another handle")
				{
				auto third = mgr.CounterSingleton<double>("zeek", "dbl-count-2", "test");
				CHECK_NE(first, third);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to counter families")
	{
	GIVEN("a telemetry manager")
		{
		NativeManager native_mgr;
		Manager mgr{opaque(&native_mgr)};
		WHEN("retrieving an IntCounter family")
			{
			auto family = mgr.CounterFamily("zeek", "requests", {"method"}, "test", "1", true);
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "requests"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"method"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "1"sv);
				CHECK_EQ(family.IsSum(), true);
				}
			AND_THEN("getOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"method", "get"}});
				auto second = family.GetOrAdd({{"method", "get"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("getOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"method", "get"}});
				auto second = family.GetOrAdd({{"method", "put"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblCounter family")
			{
			auto family = mgr.CounterFamily<double>("zeek", "runtime", {"query"}, "test", "seconds", true);
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "runtime"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"query"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "seconds"sv);
				CHECK_EQ(family.IsSum(), true);
				}
			AND_THEN("getOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"query", "foo"}});
				auto second = family.GetOrAdd({{"query", "foo"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("getOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"query", "foo"}});
				auto second = family.GetOrAdd({{"query", "bar"}});
				CHECK_NE(first, second);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to gauge singletons")
	{
	GIVEN("a telemetry manager")
		{
		NativeManager native_mgr;
		Manager mgr{opaque(&native_mgr)};
		WHEN("retrieving an IntGauge singleton")
			{
			auto first = mgr.GaugeSingleton("zeek", "int-gauge", "test");
			THEN("its initial value is zero")
				{
				CHECK_EQ(first.Value(), 0);
				}
			AND_THEN("calling Inc(), Dec(), operator++ or operator-- changes the value")
				{
				first.Inc();
				CHECK_EQ(first.Value(), 1);
				first.Inc(2);
				CHECK_EQ(first.Value(), 3);
				first.Dec();
				CHECK_EQ(first.Value(), 2);
				CHECK_EQ(++first, 3);
				CHECK_EQ(first.Value(), 3);
				CHECK_EQ(--first, 2);
				CHECK_EQ(first.Value(), 2);
				first.Dec(2);
				CHECK_EQ(first.Value(), 0);
				}
			AND_THEN("calling gaugeSingleton again for the same name returns the same handle")
				{
				auto second = mgr.GaugeSingleton("zeek", "int-gauge", "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling gaugeSingleton for a different name returns another handle")
				{
				auto third = mgr.GaugeSingleton("zeek", "int-gauge-2", "test");
				CHECK_NE(first, third);
				}
			}
		WHEN("retrieving a DblGauge singleton")
			{
			auto first = mgr.GaugeSingleton<double>("zeek", "dbl-gauge", "test");
			THEN("its initial value is zero")
				{
				CHECK_EQ(first.Value(), 0.0);
				}
			AND_THEN("calling Inc() or Dec() changes the value")
				{
				first.Inc();
				CHECK_EQ(first.Value(), 1.0);
				first.Inc(3.0);
				CHECK_EQ(first.Value(), 4.0);
				first.Dec(2.0);
				CHECK_EQ(first.Value(), 2.0);
				first.Dec();
				CHECK_EQ(first.Value(), 1.0);
				}
			AND_THEN("calling gaugeSingleton again for the same name returns the same handle")
				{
				auto second = mgr.GaugeSingleton<double>("zeek", "dbl-gauge", "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling gaugeSingleton for a different name returns another handle")
				{
				auto third = mgr.GaugeSingleton<double>("zeek", "dbl-gauge-2", "test");
				CHECK_NE(first, third);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to gauge families")
	{
	GIVEN("a telemetry manager")
		{
		NativeManager native_mgr;
		Manager mgr{opaque(&native_mgr)};
		WHEN("retrieving an IntGauge family")
			{
			auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "open-connections"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "1"sv);
				CHECK_EQ(family.IsSum(), false);
				}
			AND_THEN("getOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("getOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "quic"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblGauge family")
			{
			auto family = mgr.GaugeFamily<double>("zeek", "water-level", {"river"}, "test", "meters");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "water-level"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"river"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "meters"sv);
				CHECK_EQ(family.IsSum(), false);
				}
			AND_THEN("getOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"river", "Sacramento"}});
				auto second = family.GetOrAdd({{"river", "Sacramento"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("getOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"query", "Sacramento"}});
				auto second = family.GetOrAdd({{"query", "San Joaquin"}});
				CHECK_NE(first, second);
				}
			}
		}
	}
