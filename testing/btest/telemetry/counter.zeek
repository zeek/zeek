# @TEST-GROUP: Telemetry

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global cnt1 = Telemetry::__counter_family("cnt1", "bar", vector("dim1", "dim2"));
global cnt2 = Telemetry::__counter_family("cnt2", "bar", vector());

event zeek_init()
	{
	local cnt1_bar = Telemetry::__counter_metric_get_or_add(cnt1, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::__counter_inc(cnt1_bar);
	local cnt2_bar = Telemetry::__counter_metric_get_or_add(cnt2, table());
	Telemetry::__counter_inc(cnt2_bar);
	Telemetry::__counter_inc(cnt2_bar, 41);
	print fmt("cnt1_bar: %f", Telemetry::__counter_value(cnt1_bar));
	print fmt("cnt2_bar: %f", Telemetry::__counter_value(cnt2_bar));
	}
