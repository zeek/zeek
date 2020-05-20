# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


# enum with optional comma at end of definition
type color: enum { Red, White, Blue, };

# enum without optional comma
type city: enum { Rome, Paris };


event zeek_init()
{
	local e1: color = Blue;
	local e2: color = White;
	local e3: color = Blue;
	local e4: city = Rome;

	test_case( "enum equality comparison", e1 != e2 );
	test_case( "enum equality comparison", e1 == e3 );
	test_case( "enum equality comparison", e1 != e4 );

	# type inference
	local x = Blue;
	test_case( "type inference", x == e1 );
}

