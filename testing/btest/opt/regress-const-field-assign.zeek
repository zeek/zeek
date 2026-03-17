# @TEST-DOC: Regression test for improperly folding fields of "const" globals
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O xform %INPUT >output
# @TEST-EXEC: btest-diff output

type R: record {
	foo: count &default = 3;
};

const my_r = R();

event zeek_init()
	{
	print my_r$foo;
	my_r$foo = 9;
	print my_r$foo;
	}
