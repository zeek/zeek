#
# @TEST-EXEC: zeek -b %INPUT

event zeek_init()
	{
	local a = current_time();
	if ( a <= 0 as time )
		exit(1);
	}
