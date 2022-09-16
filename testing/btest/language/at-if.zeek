# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

function foo(c: count): bool
	{ return c == 42 ? T : F; }

global TRUE_CONDITION = T;
global xyz = 0;

event zeek_init()
{
	# Test "if" without "else"

	@if ( F )
		xyz += 1;
	@endif

	@if ( foo(0) )
		xyz += 1;
	@endif

	@if ( T && foo(42) )
		xyz += 2;
	@endif

	test_case( "@if", xyz == 2 );

	# Test "if" with an "else"

	xyz = 0;

	@if ( F )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@if...@else", xyz == 2 );

	xyz = 0;

	@if ( T && TRUE_CONDITION )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@if...@else", xyz == 1 );

}

