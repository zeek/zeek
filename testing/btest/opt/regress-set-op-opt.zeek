# @TEST-DOC: Regression test for ZAM optimizer mis-transforming set +=/-= ops
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type R: record {
	my_set: set[string];
};

event zeek_init()
	{
	local r1 = R();
	local r2 = R();

	if ( |r1$my_set| > 0 )
		print T;

	r2$my_set += r1$my_set;
	print r2;
	}
