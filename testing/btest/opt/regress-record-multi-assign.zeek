# @TEST-DOC: Regression test for assigning multiple fields in a record
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O xform %INPUT >output
# @TEST-EXEC: btest-diff output

type R: record {
	a: count;
	b: count;
};

function multi_add(x: R, y: R): R
	{
	y$a += x$b;
	y$b += x$a;
	return y;
	}

function multi_assign(x: R, y: R): R
	{
	y$a = x$b;
	y$b = x$a;
	return y;
	}

event zeek_init()
	{
	local x = R($a=3, $b=4);
	local y = R($a=33, $b=44);
	print multi_add(x, y);
	print multi_assign(x, y);
	}
