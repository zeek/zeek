#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = global_sizes();
	for ( i in a )
		{
		# the table is quite large, so just look for one item we expect
		if ( i == "zeek_init" )
			print "found zeek_init";

		}

	}
