# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

global thisisdefined = 123;

event zeek_init()
{
	local xyz = 0;

	# Test "ifdef" without "else"

	@ifdef ( notdefined )
		xyz += 1;
	@endif

	@ifdef ( thisisdefined )
		xyz += 2;
	@endif

	test_case( "@ifdef", xyz == 2 );

	# Test "ifdef" with an "else"

	xyz = 0;

	@ifdef ( doesnotexist )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifdef...@else", xyz == 2 );

	xyz = 0;

	@ifdef ( thisisdefined )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifdef...@else", xyz == 1 );

}

