#
# @TEST-EXEC: zeek -b %INPUT

event zeek_init()
	{
	local a = getpid();
	if ( a == 0 )
		exit(1);
	}
