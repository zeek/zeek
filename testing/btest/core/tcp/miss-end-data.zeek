# @TEST-EXEC: zeek -b -r $TRACES/tcp/miss_end_data.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
@load base/protocols/http

redef report_gaps_for_partial = T;

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	print "content_gap", c$id, is_orig, seq, length;
	}
