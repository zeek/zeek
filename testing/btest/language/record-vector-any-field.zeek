# @TEST-DOC: Test vectors in record consturctions when suing any fields. Regression test for #5114
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: btest-diff .stdout

type R: record {
	xs: any;
};

event zeek_init()
	{
	local r1 = R($xs=vector());
	print r1;

	local r2 = R($xs=vector(1, 2, 3));
	print r2;

	local r3 = R($xs=vector("one", "two", "three"));
	print r3;
	}

# @TEST-START-NEXT
#
# Similar as above, but relying on &default
type Rempty: record {
	xs: any &default=vector();
};

type Rcount: record {
	xs: any &default=vector(1, 2, 3);
};

type Rstring: record {
	xs: any &default=vector("one", "two", "three");
};

event zeek_init()
	{
	local r1 = Rempty();
	print r1;

	local r2 = Rcount();
	print r2;

	local r3 = Rstring();
	print r3;
	}
