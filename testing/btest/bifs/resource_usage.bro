#
# @TEST-EXEC: bro %INPUT

event bro_init()
	{
	local a = resource_usage();
	if ( a$version != bro_version() )
		exit(1);
	}
