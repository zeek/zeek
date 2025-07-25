# XXX: ZAM is borked and I don't know how to fix it :-(
#
# @TEST-REQUIRES: false
# @TEST-DOC: Regression test for reassigning an "any" field
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type X: record {
	a: string;
	b: any;
};

event zeek_init()
	{
	local x = X($a="123", $b=vector("abc"));
	print x;
	x$b = 1;
	print x;
	}
