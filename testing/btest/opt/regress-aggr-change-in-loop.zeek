# @TEST-DOC: Regression test for an aggregate in a CSE changing inside a loop
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type Data: record {
	hash: string;
};

global map: table[string] of Data;

function traverse_map(hash: string)
	{
	local tmp = map[hash];

	if ( tmp$hash == "" )
		return;

	while ( tmp$hash in map )
		{
		# Prior to the fix, the value of tmp$hash computed in the
		# earlier "if" statement was used here, rather than the
		# optimizer recognizing that "tmp" can have changed at this
		# point due to the loop, and thus that value can be stale.
		# That led to an infinite loop here.
		tmp = map[tmp$hash];
		print tmp;
		}
	}

event zeek_init()
	{
	map["foo"] = Data($hash="bar");
	map["bar"] = Data($hash="bletch");
	map["bletch"] = Data($hash="xyzzy");
	traverse_map("foo");
	print "done";
	}
