#
# @TEST-EXEC: bro -b %INPUT

event bro_init()
	{
	local a = current_analyzer();
	if ( a != 0 )
		exit(1);

	# TODO: add a test for non-zero return value
	}
