#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = global_ids();
	for ( i in a )
		{
		# the table is quite large, so just print one item we expect
		if ( i == "zeek_init" )
			print a[i]$type_name;

		}

	}
