#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = global_ids();
	for ( i in a )
		{
		# the table is quite large, so just print one item we expect
		if ( i == "bro_init" )
			print a[i]$type_name;

		}

	}
