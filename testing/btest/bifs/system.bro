#
# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = system("echo thistest > out");
	if ( a != 0 )
		exit(1);

	local b = system("");
	if ( b == 0 )
		exit(1);

	}
