# @TEST-GROUP: Telemetry

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global gg1 = Telemetry::int_gauge_family("gg1", "bar", vector("dim1", "dim2"));
global gg2_bar = Telemetry::int_gauge_singleton("gg2", "bar");
global gg3 = Telemetry::dbl_gauge_family("gg3", "bar", vector("dim1", "dim2"));
global gg4_bar = Telemetry::dbl_gauge_singleton("gg4", "bar");

event zeek_init()
	{
	local gg1_bar = Telemetry::int_gauge_metric_get_or_add(gg1, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::int_gauge_inc(gg1_bar);
	Telemetry::int_gauge_inc(gg2_bar);
	Telemetry::int_gauge_inc(gg2_bar, 41);
	Telemetry::int_gauge_dec(gg2_bar);
	Telemetry::int_gauge_dec(gg2_bar, 18);
	print fmt("gg1_bar: %d", Telemetry::int_gauge_value(gg1_bar));
	print fmt("gg2_bar: %d", Telemetry::int_gauge_value(gg2_bar));
	local gg3_bar = Telemetry::dbl_gauge_metric_get_or_add(gg3, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::dbl_gauge_inc(gg3_bar);
	Telemetry::dbl_gauge_inc(gg4_bar);
	Telemetry::dbl_gauge_inc(gg4_bar, 41.0);
	Telemetry::dbl_gauge_dec(gg4_bar);
	Telemetry::dbl_gauge_dec(gg4_bar, 18.0);
	print fmt("gg3_bar: %f", Telemetry::dbl_gauge_value(gg3_bar));
	print fmt("gg4_bar: %f", Telemetry::dbl_gauge_value(gg4_bar));
	}

