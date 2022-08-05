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

	xyz = 0;

	@ifdef ( Bar )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifdef module name", xyz == 1 );

	xyz = 0;

	@ifdef ( Bar::exists )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@ifdef child variable", xyz == 1 );
}

@TEST-END-FILE

@TEST-START-FILE bar.zeek

module Bar;

export {
  option exists = T;
}

@TEST-END-FILE
