#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = global_sizes();
	for ( i in a )
		{
		# the table is quite large, so just look for one item we expect
		if ( i == "bro_init" )
			print "found bro_init";

		}

	}
