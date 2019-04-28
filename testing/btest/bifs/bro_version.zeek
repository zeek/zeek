#
# @TEST-EXEC: bro -b %INPUT

event zeek_init()
	{
	local a = bro_version();
	if ( |a| == 0 )
		exit(1);
	}
