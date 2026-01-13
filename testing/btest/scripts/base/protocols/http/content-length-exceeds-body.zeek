# Authorization: Basic password has a colon in its value
#
# @TEST-EXEC: zeek -b -r $TRACES/http/content-length-exceeds-body.pcap %INPUT >out
# @TEST-EXEC: zeek-cut -m < http.log > http.log.cut
# @TEST-EXEC: zeek-cut -m < weird.log > weird.log.cut
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff weird.log.cut

@load base/protocols/http
@load base/frameworks/notice/weird

event http_event(c: connection, event_type: string, detail: string)
	{
	print "http_event", event_type, detail;
	}
