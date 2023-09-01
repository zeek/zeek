# @TEST-DOC: Pcap has a gap for the server side. This previously caused unbounded state growth in c$http_state$pending.
#
# @TEST-EXEC: zcat <$TRACES/http/1000-requests-one-dropped-response.pcap.gz | zeek -C -b -r - %INPUT >out
# @TEST-EXEC: echo "total http.log lines" >>out
# @TEST-EXEC: grep -v '^#' http.log | wc -l | sed 's/ //g' >>out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http

event connection_state_remove(c: connection)
	{
	if ( c?$http_state )
		print "http_state pending", |c$http_state$pending|;
	}
