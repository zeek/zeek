# @TEST-DOC: A FTP connection with a reassembly gap that previously caused 100k events to be queued, now Zeek flushes every 2000 events, reporting 49 overflow drains via metrics.
#
# @TEST-EXEC: zcat <$TRACES/ftp/ftp-request-event-memory-exhaustion.pcap.gz | zeek -b -r - %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird
@load base/frameworks/telemetry
@load base/protocols/conn
@load base/protocols/ftp

event zeek_done()
	{
	local ms = Telemetry::collect_metrics("zeek", "events*");
	ms += Telemetry::collect_metrics("zeek", "event_queue_*");

	for (_, m in ms)
		print m$opts$name, m$label_values, m$value;
	}
