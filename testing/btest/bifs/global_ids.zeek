#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = global_ids();
	for ( k, v in a )
		{
		# the table is quite large, so just print the following.
		if ( k in set("zeek_init", "Log::write", "Site::local_nets") )
			{
			print k, v$type_name;
			assert type_name(lookup_ID(k)) == v$type_name, fmt("%s vs %s", type_name(lookup_ID(k)), v$type_name);
			}
		}

	}
