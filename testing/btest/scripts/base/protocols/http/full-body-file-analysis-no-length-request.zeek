# @TEST-DOC: A request with a multipart Content-Type but no length has no body. With HTTP::enable_full_body_file_analysis, the data that follows a CONNECT or WebSocket Upgrade request must not end up in a full body file for the request.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/full-body-file-analysis-no-length-request.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

@load base/protocols/http
@load base/protocols/websocket
@load base/frameworks/analyzer/dpd

redef HTTP::enable_full_body_file_analysis = T;

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	print "file", c$id$orig_p, is_orig ? "orig" : "resp";
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	print "message", c$id$orig_p, is_orig ? "orig" : "resp", stat$body_length;
	}
