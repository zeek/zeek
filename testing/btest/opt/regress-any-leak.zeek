# @TEST-DOC: Regression test for leak when mixing "any" types (affected both ZAM and non-ZAM)
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output
# @TEST-EXEC: btest-diff output

type X: record {
	a: string;
};

event zeek_init()
	{
	local vec: vector of any;
	vec += X($a="abc-1");
	print vec;
	vec[0] = 1;
	print vec;
	}
