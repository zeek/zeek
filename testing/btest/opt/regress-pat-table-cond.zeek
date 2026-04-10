# @TEST-DOC: Regression test for pattern table lookup used as a conditional
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -O ZAM -b %INPUT >output
# @TEST-EXEC: btest-diff output

global prefixes: table[pattern] of string;

event zeek_init()
	{
	local pat = string_to_pattern(convert_for_pattern("z/t/") + ".*", F);
	prefixes[pat] = "working OK";

	# We test two paths, one where it's a variable we're checking/accessing,
	# the other a constant.
	local var = "z/t/morestuff";

	# The following fakes out ZAM (since it refers to a global) into not
	# optimizing "var" into constant propagation.
	if ( |prefixes| == 0 )
		var = "nope";

	if ( var in prefixes )
		print prefixes[var];

	# Now test the same but with a constant.
	if ( "z/t/morestuff" in prefixes )
		print prefixes["z/t/morestuff"];
	}
