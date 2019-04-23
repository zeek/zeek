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

	# Test "ifndef" without "else"

	@ifndef ( notdefined )
		xyz += 1;
	@endif

	@ifndef ( thisisdefined )
		xyz += 2;
	@endif

	test_case( "@ifndef", xyz == 1 );

	# Test "ifndef" with an "else"

	xyz = 0;

	@ifndef ( doesnotexist )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifndef...@else", xyz == 1 );

	xyz = 0;

	@ifndef ( thisisdefined )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifndef...@else", xyz == 2 );

}

