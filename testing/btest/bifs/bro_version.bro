#
# @TEST-EXEC: bro -b %INPUT

event bro_init()
	{
	local a = bro_version();
	if ( |a| == 0 )
		exit(1);
	}
