# @TEST-DOC: Concurrent range requests for the same URL share one entity file. With HTTP::enable_full_body_file_analysis, each response must still get its own full body file.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/concurrent-range-requests.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m uid fuid parent_fuid seen_bytes total_bytes missing_bytes files.log

@load base/protocols/http

redef HTTP::enable_full_body_file_analysis = T;

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( ! is_orig )
		print c$uid, c$http?$resp_body_fuid ? c$http$resp_body_fuid : "-", stat$body_length;
	}
