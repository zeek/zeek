# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event bro_init()
{
	local xyz = 0;

	# Test "if" without "else"

	@if ( F )
		xyz += 1;
	@endif

	@if ( T )
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

	@if ( T )
		xyz += 1;
	@else
		xyz += 2;
	@endif

	test_case( "@if...@else", xyz == 1 );

}

