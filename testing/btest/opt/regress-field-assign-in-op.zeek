# @TEST-DOC: Regression test for assigning a record field to an "in" operation
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type r1: record {
	is_free: bool;
};

type r2: record {
	s: string;
	ss: string_set;
};

event zeek_init()
	{
	local l1 = r1($is_free = F);
	local l2 = r2($s="foo", $ss=set("bar", "bletch"));
	l1$is_free = l2$s in l2$ss;
	print l1$is_free ? "yep" : "nope";
	}
