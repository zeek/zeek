# @TEST-GROUP: Telemetry

# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

const int_bounds = vector(+10, +20);
const dbl_bounds = vector(10.0, 20.0);

global hst1 = Telemetry::__int_histogram_family("hst1", "bar", vector("dim1", "dim2"), int_bounds);
global hst2 = Telemetry::__int_histogram_family("hst2", "bar", vector(), int_bounds);
global hst3 = Telemetry::__dbl_histogram_family("hst3", "bar", vector("dim1", "dim2"), dbl_bounds);
global hst4 = Telemetry::__dbl_histogram_family("hst4", "bar", vector(), dbl_bounds);

event zeek_init()
	{
	local hst1_bar = Telemetry::__int_histogram_metric_get_or_add(hst1, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::__int_histogram_observe(hst1_bar, 1);
	Telemetry::__int_histogram_observe(hst1_bar, 11);
	local hst2_bar = Telemetry::__int_histogram_metric_get_or_add(hst2, table());
	Telemetry::__int_histogram_observe(hst2_bar, 31337);
	print fmt("hst1_bar: %d", Telemetry::__int_histogram_sum(hst1_bar));
	print fmt("hst2_bar: %d", Telemetry::__int_histogram_sum(hst2_bar));
	local hst3_bar = Telemetry::__dbl_histogram_metric_get_or_add(hst3, table(["dim1"] = "val1", ["dim2"] = "val2"));
	Telemetry::__dbl_histogram_observe(hst3_bar, 2.0);
	Telemetry::__dbl_histogram_observe(hst3_bar, 4.0);
	local hst4_bar = Telemetry::__dbl_histogram_metric_get_or_add(hst4, table());
	Telemetry::__dbl_histogram_observe(hst4_bar, 64.0);
	print fmt("hst3_bar: %f", Telemetry::__dbl_histogram_sum(hst3_bar));
	print fmt("hst4_bar: %f", Telemetry::__dbl_histogram_sum(hst4_bar));
	}
