# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
	{
	print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
	}

event zeek_init()
	{
	# "b" is not a copy of "a"
	local a: set[string] = set("this", "test");
	local b: set[string] = a;

	delete a["this"];

	test_case( "direct assignment", |b| == 1 && "this" !in b );

	# "d" is a copy of "c"
	local c: set[string] = set("this", "test");
	local d: set[string] = copy(c);

	delete c["this"];

	test_case( "using copy", |d| == 2 && "this" in d);
	}

type myrec: record {
	a: count;
};

event zeek_init()
	{
	local v: vector of myrec;
	local t: table[count] of myrec;
	local mr = myrec($a = 42);

	t[0] = mr;
	t[1] = mr;
	local tc = copy(t);
	print same_object(t, tc), same_object(tc[0], tc[1]);

	v[0] = mr;
	v[1] = mr;
	local vc = copy(v);
	print same_object(v, vc), same_object(vc[0], vc[1]);
	print tc[0], tc[1], vc[0], vc[1];
	}

