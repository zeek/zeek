#
# @TEST-EXEC: bro -b %INPUT

event bro_init()
	{
	local a = current_time();
	if ( a <= double_to_time(0) )
		exit(1);
	}
