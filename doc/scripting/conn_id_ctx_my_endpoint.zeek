type MyEndpoint: record {
	ctx: conn_id_ctx;
	a: addr;
};

global talks_with_service: table[MyEndpoint] of set[string] &default_insert=set();

event connection_state_remove(c: connection)
	{
	local endp = MyEndpoint($ctx=c$id$ctx, $a=c$id$orig_h);

	for ( s in c$service )
		add talks_with_service[endp][s];
	}

event zeek_done()
	{
	for ( e, es in talks_with_service )
		print e, join_string_set(es, ", ");
	}

