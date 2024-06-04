# @TEST-GROUP: Telemetry

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

const dbl_bounds = vector(10.0, 20.0);

global hst1 = Telemetry::__histogram_family("hst1", "bar", vector("dim1", "dim2"), dbl_bounds);
global hst2 = Telemetry::__histogram_family("hst2", "bar", vector(), dbl_bounds);

event zeek_init()
	{
	local hst1_bar = Telemetry::__histogram_metric_get_or_add(hst1, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::__histogram_observe(hst1_bar, 2.0);
	Telemetry::__histogram_observe(hst1_bar, 4.0);
	local hst2_bar = Telemetry::__histogram_metric_get_or_add(hst2, table());
	Telemetry::__histogram_observe(hst2_bar, 64.0);
	print fmt("hst1_bar: %f", Telemetry::__histogram_sum(hst1_bar));
	print fmt("hst2_bar: %f", Telemetry::__histogram_sum(hst2_bar));
	}
