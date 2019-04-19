#
# @TEST-EXEC: bro -b %INPUT

event zeek_init()
	{
	local a = gethostname();
	if ( |a| == 0 )
		exit(1);
	}
