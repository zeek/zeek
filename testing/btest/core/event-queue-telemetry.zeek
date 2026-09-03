# @TEST-DOC: Verify the metrics from the EventMgr
#
#
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/frameworks/telemetry

event zeek_done()
	{
	local ms = Telemetry::collect_metrics("zeek", "events*");
	ms += Telemetry::collect_metrics("zeek", "event_queue_*");

	for (_, m in ms)
		print m$opts$name, m$label_values, m$value;
	}
