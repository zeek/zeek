#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "dh3Hie02uh^s#Sdf9L3frd243h$d78r2G4cM6*Q05d(7rh46f!0|4-f";
	local handle = entropy_test_init();
	if ( ! entropy_test_add(handle, a) )
		exit(1);
	print entropy_test_finish(handle);

	local b = "0011000aaabbbbcccc000011111000000000aaaabbbbcccc0000000";
	handle = entropy_test_init();
	if ( ! entropy_test_add(handle, b) )
		exit(1);
	print entropy_test_finish(handle);
	}
