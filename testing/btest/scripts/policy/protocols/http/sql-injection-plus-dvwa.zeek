# @TEST-EXEC: zeek -C -r $TRACES/http/cooper-grill-dvwa.pcapng -b %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut -m uid method host uri tags < http.log > http.log.cut
# @TEST-EXEC: btest-diff http.log.cut

@load base/protocols/http
@load protocols/http/detect-sqli

event connection_state_remove(c: connection)
	{
	if ( c?$http )
		print c$uid, c$id, cat(c$http$tags);
	}
