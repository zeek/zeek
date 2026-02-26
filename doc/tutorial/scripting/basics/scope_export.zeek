module AllowList;

export {
	const allow_list: set[addr] = [192.168.1.8];
}

event new_connection(c: connection)
	{
	if ( c$id$orig_h !in allow_list )
		print fmt("Address %s is not allowed!", c$id$orig_h);
	if ( c$id$resp_h !in allow_list )
		print fmt("Address %s is not allowed!", c$id$resp_h);
	}
