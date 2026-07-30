# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff-remove-abspath output

type myvec: vector of any;

function check(a: any)
	{
	print a is myvec;
	print a as myvec;
	}

event zeek_init()
	{
	local v = myvec("one", "two", 3);
	check(v);
	local sv = string_vec("one", "two", "three");
	check(sv);
	}
