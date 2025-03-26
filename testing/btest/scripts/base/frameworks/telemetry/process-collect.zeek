# @TEST-DOC: Calling collect_metrics() invokes callbacks for process (and other) metrics.
# Not compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -r $TRACES/http/get.trace -b %INPUT >out
# @TEST-EXEC: btest-diff out


@load base/frameworks/telemetry

function print_metrics(ms: vector of Telemetry::Metric) {
	for (_, m in ms)
		print m$opts$name, m$label_values, m$value > 0.0 ? ">0.0, good" : "0.0, bad";
}

event zeek_init()
	{
	print "zeek_init";
	local ms = Telemetry::collect_metrics("process");
	print_metrics(ms);
	}

event zeek_done()
	{
	print "zeek_done";
	local ms = Telemetry::collect_metrics("process");
	print_metrics(ms);
	}
