# @TEST-DOC: Calling collect_metrics() invokes Telemetry::sync.
# Not compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out


@load base/frameworks/telemetry

global connections_by_proto_cf = Telemetry::register_counter_family([
	$prefix="btest",
	$name="connections",
	$unit="",
	$help_text="Total number of monitored connections",
	$label_names=vector("proto")
]);

function print_metrics(ms: vector of Telemetry::Metric) {
	for (_, m in ms) {
		print m$opts$name, m$label_values, m$value;
	}
}

event zeek_init()
	{
	print "node up";
	local ms = Telemetry::collect_metrics("btest");
	print_metrics(ms);
	ms = Telemetry::collect_metrics("btest");
	print_metrics(ms);
	ms = Telemetry::collect_metrics("btest");
	print_metrics(ms);
	local hm = Telemetry::collect_histogram_metrics("btest");
	print_metrics(ms);
	}


global sync_calls = 0;

hook Telemetry::sync()
	{
	++sync_calls;
	local proto = sync_calls == 1 ? "tcp" : "udp";
	print "sync", sync_calls, proto;
	Telemetry::counter_family_inc(connections_by_proto_cf, vector(proto));
	}
