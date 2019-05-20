#
# @TEST-EXEC: zeek -b %INPUT

event zeek_init()
	{
	local a = current_analyzer();
	if ( a != 0 )
		exit(1);

	# TODO: add a test for non-zero return value
	}
