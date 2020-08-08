# @TEST-EXEC: zeek -b -r $TRACES/ipv6-http-atomic-frag.trace %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/protocols/http

event new_connection(c: connection)
	{
	if ( c$id$resp_p == 80/tcp )
		print c$id;
	}
