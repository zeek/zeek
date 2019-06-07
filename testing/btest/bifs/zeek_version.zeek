#
# @TEST-EXEC: zeek -b %INPUT

event zeek_init()
	{
	local a = zeek_version();
	if ( |a| == 0 )
		exit(1);
	}
