# A version of sql-injection-plus-dvwa.zeek that uses its replacement script.
#
# @TEST-EXEC: zeek -C -r $TRACES/http/cooper-grill-dvwa.pcapng -b %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: zeek-cut -m uid method host uri tags < http.log > http.log.cut
# @TEST-EXEC: btest-diff http.log.cut

@load base/protocols/http
@load protocols/http/detect-sql-injection

redef HTTP::sqli_requests_threshold = 3;

event connection_state_remove(c: connection)
	{
	if ( c?$http )
		print c$uid, c$id, cat(c$http$tags);
	}
