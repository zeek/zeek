#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = system("echo thistest > out");
	if ( a != 0 )
		exit(1);
	}
