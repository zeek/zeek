# @TEST-DOC: Query for zeek event-handler-invocations metrics counting number of times handlers were called.

# Note compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC-FAIL: test -f reporter.log

@load base/frameworks/telemetry


event zeek_done() &priority=-100
	{
	local ms = Telemetry::collect_metrics("zeek", "event_handler_invocations");
	for ( _, m in ms )
		{
		if ( /zeek_.*|connection_.*/ in cat(m$labels))
			print m$opts$name, m$labels, m$count_value;
		}
	}
