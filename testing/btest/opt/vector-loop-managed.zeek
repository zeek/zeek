# @TEST-DOC: Regression test for memory leak when iterating over records of managed types.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type X: record {
	a: string;
};

event zeek_init()
	{
	local vec1 = vector(X($a="123"), X($a="456"));
	local vec2 = vector(vector(1), vector(2));

	for ( i, r in vec1 )
		print i, r;

	for ( _, r in vec1 )
		print r;

	for ( j, v in vec2 )
		print j, v;

	for ( _, v in vec2 )
		print v;
	}
