#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = vector( 5, 3, 8 );

	print |a|;

	if ( resize(a, 5) != 3 )
		exit(1);

	print |a|;

	if ( resize(a, 0) != 5 )
		exit(1);

	print |a|;

	if ( resize(a, 7) != 0 )
		exit(1);

	print |a|;

	}
