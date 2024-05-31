# @TEST-GROUP: Telemetry

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global gg1 = Telemetry::__gauge_family("gg1", "bar", vector("dim1", "dim2"));
global gg2 = Telemetry::__gauge_family("gg2", "bar", vector());

event zeek_init()
	{
	local gg1_bar = Telemetry::__gauge_metric_get_or_add(gg1, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::__gauge_inc(gg1_bar);
	local gg2_bar = Telemetry::__gauge_metric_get_or_add(gg2, table());
	Telemetry::__gauge_inc(gg2_bar);
	Telemetry::__gauge_inc(gg2_bar, 41.0);
	Telemetry::__gauge_dec(gg2_bar);
	Telemetry::__gauge_dec(gg2_bar, 18.0);
	print fmt("gg1_bar: %f", Telemetry::__gauge_value(gg1_bar));
	print fmt("gg2_bar: %f", Telemetry::__gauge_value(gg2_bar));
	}
