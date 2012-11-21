#
# @TEST-EXEC: bro %INPUT

event bro_init()
	{
	local a = get_matcher_stats();
	if ( a$matchers == 0 )
		exit(1);
	}
