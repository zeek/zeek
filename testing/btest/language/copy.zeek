# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

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

