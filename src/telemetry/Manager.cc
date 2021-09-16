// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#include <thread>

#include "zeek/3rdparty/doctest.h"
#include "zeek/telemetry/Detail.h"
#include "zeek/telemetry/Timer.h"

#include "caf/telemetry/metric_registry.hpp"

namespace zeek::telemetry
	{

Manager::~Manager() { }

void Manager::InitPostScript() { }

IntCounterFamily Manager::IntCounterFam(std::string_view prefix, std::string_view name,
                                        Span<const std::string_view> labels,
                                        std::string_view helptext, std::string_view unit,
                                        bool is_sum)
	{
	return with_native_labels(labels,
	                          [&, this](auto xs)
	                          {
								  auto ptr = deref(pimpl).counter_family(prefix, name, xs, helptext,
		                                                                 unit, is_sum);
								  return IntCounterFamily{opaque(ptr)};
							  });
	}

DblCounterFamily Manager::DblCounterFam(std::string_view prefix, std::string_view name,
                                        Span<const std::string_view> labels,
                                        std::string_view helptext, std::string_view unit,
                                        bool is_sum)
	{
	return with_native_labels(labels,
	                          [&, this](auto xs)
	                          {
								  auto ptr = deref(pimpl).counter_family<double>(
									  prefix, name, xs, helptext, unit, is_sum);
								  return DblCounterFamily{opaque(ptr)};
							  });
	}

IntGaugeFamily Manager::IntGaugeFam(std::string_view prefix, std::string_view name,
                                    Span<const std::string_view> labels, std::string_view helptext,
                                    std::string_view unit, bool is_sum)
	{
	return with_native_labels(labels,
	                          [&, this](auto xs)
	                          {
								  auto ptr = deref(pimpl).gauge_family(prefix, name, xs, helptext,
		                                                               unit, is_sum);
								  return IntGaugeFamily{opaque(ptr)};
							  });
	}

DblGaugeFamily Manager::DblGaugeFam(std::string_view prefix, std::string_view name,
                                    Span<const std::string_view> labels, std::string_view helptext,
                                    std::string_view unit, bool is_sum)
	{
	return with_native_labels(labels,
	                          [&, this](auto xs)
	                          {
								  auto ptr = deref(pimpl).gauge_family<double>(
									  prefix, name, xs, helptext, unit, is_sum);
								  return DblGaugeFamily{opaque(ptr)};
							  });
	}

IntHistogramFamily Manager::IntHistoFam(std::string_view prefix, std::string_view name,
                                        Span<const std::string_view> labels,
                                        Span<const int64_t> ubounds, std::string_view helptext,
                                        std::string_view unit, bool is_sum)
	{
	return with_native_labels(
		labels,
		[&, this](auto xs)
		{
			auto bounds = caf::span<const int64_t>{ubounds.data(), ubounds.size()};
			auto ptr =
				deref(pimpl).histogram_family(prefix, name, xs, bounds, helptext, unit, is_sum);
			return IntHistogramFamily{opaque(ptr)};
		});
	}

DblHistogramFamily Manager::DblHistoFam(std::string_view prefix, std::string_view name,
                                        Span<const std::string_view> labels,
                                        Span<const double> ubounds, std::string_view helptext,
                                        std::string_view unit, bool is_sum)
	{
	return with_native_labels(
		labels,
		[&, this](auto xs)
		{
			auto bounds = caf::span<const double>{ubounds.data(), ubounds.size()};
			auto ptr = deref(pimpl).histogram_family<double>(prefix, name, xs, bounds, helptext,
		                                                     unit, is_sum);
			return DblHistogramFamily{opaque(ptr)};
		});
	}

	} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace std::literals;
using namespace zeek::telemetry;

using NativeManager = caf::telemetry::metric_registry;

namespace
	{

template <class T> auto toVector(zeek::Span<T> xs)
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
			THEN("its initial value is zero") { CHECK_EQ(first.Value(), 0); }
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
			THEN("its initial value is zero") { CHECK_EQ(first.Value(), 0.0); }
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
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"method", "get"}});
				auto second = family.GetOrAdd({{"method", "get"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"method", "get"}});
				auto second = family.GetOrAdd({{"method", "put"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblCounter family")
			{
			auto family =
				mgr.CounterFamily<double>("zeek", "runtime", {"query"}, "test", "seconds", true);
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "runtime"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"query"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "seconds"sv);
				CHECK_EQ(family.IsSum(), true);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"query", "foo"}});
				auto second = family.GetOrAdd({{"query", "foo"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
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
			THEN("its initial value is zero") { CHECK_EQ(first.Value(), 0); }
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
			THEN("its initial value is zero") { CHECK_EQ(first.Value(), 0.0); }
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
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "quic"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblGauge family")
			{
			auto family =
				mgr.GaugeFamily<double>("zeek", "water-level", {"river"}, "test", "meters");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "water-level"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"river"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "meters"sv);
				CHECK_EQ(family.IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"river", "Sacramento"}});
				auto second = family.GetOrAdd({{"river", "Sacramento"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"query", "Sacramento"}});
				auto second = family.GetOrAdd({{"query", "San Joaquin"}});
				CHECK_NE(first, second);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to histogram singletons")
	{
	GIVEN("a telemetry manager")
		{
		NativeManager native_mgr;
		Manager mgr{opaque(&native_mgr)};
		WHEN("retrieving an IntHistogram singleton")
			{
			const auto max_int = std::numeric_limits<int64_t>::max();
			int64_t buckets[] = {10, 20};
			auto first = mgr.HistogramSingleton("zeek", "int-hist", buckets, "test");
			THEN("it initially has no observations")
				{
				REQUIRE_EQ(first.NumBuckets(), 3u);
				CHECK_EQ(first.Sum(), 0);
				CHECK_EQ(first.CountAt(0), 0);
				CHECK_EQ(first.CountAt(1), 0);
				CHECK_EQ(first.CountAt(2), 0);
				CHECK_EQ(first.UpperBoundAt(0), 10);
				CHECK_EQ(first.UpperBoundAt(1), 20);
				CHECK_EQ(first.UpperBoundAt(2), max_int);
				}
			AND_THEN("calling Observe() increments bucket counters")
				{
				first.Observe(1);
				first.Observe(9);
				first.Observe(10);
				first.Observe(11);
				first.Observe(19);
				first.Observe(20);
				first.Observe(21);
				CHECK_EQ(first.Sum(), 91);
				CHECK_EQ(first.CountAt(0), 3);
				CHECK_EQ(first.CountAt(1), 3);
				CHECK_EQ(first.CountAt(2), 1);
				}
			AND_THEN("calling HistogramSingleton again for the same name returns the same handle")
				{
				auto second = mgr.HistogramSingleton("zeek", "int-hist", buckets, "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling HistogramSingleton for a different name returns another handle")
				{
				auto third = mgr.HistogramSingleton("zeek", "int-hist-2", buckets, "test");
				CHECK_NE(first, third);
				}
			}
		WHEN("retrieving a DblHistogram singleton")
			{
			double buckets[] = {10.0, 20.0};
			auto first = mgr.HistogramSingleton<double>("zeek", "dbl-count", buckets, "test");
			THEN("it initially has no observations")
				{
				REQUIRE_EQ(first.NumBuckets(), 3u);
				CHECK_EQ(first.Sum(), 0.0);
				CHECK_EQ(first.CountAt(0), 0);
				CHECK_EQ(first.CountAt(1), 0);
				CHECK_EQ(first.CountAt(2), 0);
				CHECK_EQ(first.UpperBoundAt(0), 10.0);
				CHECK_EQ(first.UpperBoundAt(1), 20.0);
				}
			AND_THEN("calling Observe() increments bucket counters")
				{
				first.Observe(2.0);
				first.Observe(4.0);
				first.Observe(8.0);
				first.Observe(16.0);
				first.Observe(32.0);
				CHECK_EQ(first.Sum(), 62.0);
				CHECK_EQ(first.CountAt(0), 3);
				CHECK_EQ(first.CountAt(1), 1);
				CHECK_EQ(first.CountAt(2), 1);
				}
			AND_THEN("calling histogramSingleton again for the same name returns the same handle")
				{
				auto second = mgr.HistogramSingleton<double>("zeek", "dbl-count", buckets, "test");
				CHECK_EQ(first, second);
				}
			AND_THEN("calling histogramSingleton for a different name returns another handle")
				{
				auto third = mgr.HistogramSingleton<double>("zeek", "dbl-count-2", buckets, "test");
				CHECK_NE(first, third);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to histogram families")
	{
	GIVEN("a telemetry manager")
		{
		NativeManager native_mgr;
		Manager mgr{opaque(&native_mgr)};
		WHEN("retrieving an IntHistogram family")
			{
			int64_t buckets[] = {10, 20};
			auto family =
				mgr.HistogramFamily("zeek", "payload-size", {"protocol"}, buckets, "test", "bytes");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "payload-size"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "bytes"sv);
				CHECK_EQ(family.IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "udp"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblHistogram family")
			{
			double buckets[] = {10.0, 20.0};
			auto family = mgr.HistogramFamily<double>("zeek", "parse-time", {"protocol"}, buckets,
			                                          "test", "seconds");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family.Prefix(), "zeek"sv);
				CHECK_EQ(family.Name(), "parse-time"sv);
				CHECK_EQ(toVector(family.LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family.Helptext(), "test"sv);
				CHECK_EQ(family.Unit(), "seconds"sv);
				CHECK_EQ(family.IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family.GetOrAdd({{"protocol", "tcp"}});
				auto second = family.GetOrAdd({{"protocol", "udp"}});
				CHECK_NE(first, second);
				}
			AND_THEN("Timers add observations to histograms")
				{
				auto hg = family.GetOrAdd({{"protocol", "tst"}});
				CHECK_EQ(hg.Sum(), 0.0);
					{
					Timer observer{hg};
					std::this_thread::sleep_for(1ms);
					}
				CHECK_NE(hg.Sum(), 0.0);
				}
			}
		}
	}
