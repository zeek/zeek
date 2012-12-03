#
# @TEST-EXEC: bro -b %INPUT

event bro_init()
	{
	local a = resource_usage();
	if ( a$version != bro_version() )
		exit(1);
	}
