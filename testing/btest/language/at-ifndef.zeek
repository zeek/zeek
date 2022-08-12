# @TEST-EXEC: zeek -b bar.zeek main.zeek >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@TEST-START-FILE main.zeek

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

global thisisdefined = 123;
global xyz = 0;

event zeek_init()
{
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

	xyz = 0;

	@ifndef ( Bar )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifndef module name", xyz == 2 );

	xyz = 0;

	@ifndef ( Bar::exists )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifndef child variable", xyz == 2 );

}

@TEST-END-FILE

@TEST-START-FILE bar.zeek

module Bar;

export {
  option exists = T;
}

@TEST-END-FILE
