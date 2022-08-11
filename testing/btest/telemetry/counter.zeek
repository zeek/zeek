# @TEST-GROUP: Telemetry

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global cnt1 = Telemetry::__int_counter_family("cnt1", "bar", vector("dim1", "dim2"));
global cnt2 = Telemetry::__int_counter_family("cnt2", "bar", vector());
global cnt3 = Telemetry::__dbl_counter_family("cnt3", "bar", vector("dim1", "dim2"));
global cnt4 = Telemetry::__dbl_counter_family("cnt4", "bar", vector());

event zeek_init()
	{
	local cnt1_bar = Telemetry::__int_counter_metric_get_or_add(cnt1, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::__int_counter_inc(cnt1_bar);
	local cnt2_bar = Telemetry::__int_counter_metric_get_or_add(cnt2, table());
	Telemetry::__int_counter_inc(cnt2_bar);
	Telemetry::__int_counter_inc(cnt2_bar, 41);
	print fmt("cnt1_bar: %d", Telemetry::__int_counter_value(cnt1_bar));
	print fmt("cnt2_bar: %d", Telemetry::__int_counter_value(cnt2_bar));
	local cnt3_bar = Telemetry::__dbl_counter_metric_get_or_add(cnt3, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::__dbl_counter_inc(cnt3_bar);
	local cnt4_bar = Telemetry::__dbl_counter_metric_get_or_add(cnt4, table());
	Telemetry::__dbl_counter_inc(cnt4_bar);
	Telemetry::__dbl_counter_inc(cnt4_bar, 41.0);
	print fmt("cnt3_bar: %f", Telemetry::__dbl_counter_value(cnt3_bar));
	print fmt("cnt4_bar: %f", Telemetry::__dbl_counter_value(cnt4_bar));
	}
