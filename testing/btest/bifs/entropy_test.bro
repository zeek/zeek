#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "dh3Hie02uh^s#Sdf9L3frd243h$d78r2G4cM6*Q05d(7rh46f!0|4-f";
	if ( entropy_test_init(1) != T )
		exit(1);

	if ( entropy_test_add(1, a) != T )
		exit(1);

	print entropy_test_finish(1);

	local b = "0011000aaabbbbcccc000011111000000000aaaabbbbcccc0000000";
	if ( entropy_test_init(2) != T )
		exit(1);

	if ( entropy_test_add(2, b) != T )
		exit(1);

	print entropy_test_finish(2);
	}
