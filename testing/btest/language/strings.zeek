# @TEST-EXEC: zeek -b %INPUT  >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

# Demo policy for string functions
#

event zeek_init()
{
	local s1: string = "broisaveryneatids";

	print fmt("Input string: %s", s1);
	print fmt();
	print fmt("String splitting");
	print fmt("----------------");

	local idx1: index_vec;

	idx1[0] =  0; # We really need initializers for vectors ...
	idx1[1] =  3;
	idx1[2] =  5;
	idx1[3] =  6;
	idx1[4] = 10;
	idx1[5] = 14;

	print fmt("Splitting '%s' at %d points in zero-indexed mode...", s1, |idx1|);
	local res_split: string_vec = str_split_indices(s1, idx1);

	for ( i in res_split )
		print res_split[i];

	print fmt();
	print fmt("Substrings");
	print fmt("----------");
	print fmt("3@0: %s", sub_bytes(s1, 0, 3));
	print fmt("5@2: %s", sub_bytes(s1, 2, 5));
	print fmt("7@4: %s", sub_bytes(s1, 4, 7));
	print fmt("10@10: %s", sub_bytes(s1, 10, 10));
	print fmt();


	print fmt("Finding strings");
	print fmt("---------------");
	print fmt("isa: %d", strstr(s1, "isa"));
	print fmt("very: %d", strstr(s1, "very"));
	print fmt("ids: %d", strstr(s1, "ids"));
	print fmt("nono: %d", strstr(s1, "nono"));
}
