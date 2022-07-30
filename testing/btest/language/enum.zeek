# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


# enum with optional comma at end of definition
type color: enum { Red, White, Blue, };

# enum without optional comma
type city: enum { Rome, Paris };

global e1: color = Blue;
global e2: color = White;
global e3: color = Blue;
global e4: city = Rome;
global x = Blue;

event zeek_init()
{
	test_case( "enum equality comparison", e1 != e2 );
	test_case( "enum equality comparison", e1 == e3 );
	test_case( "enum equality comparison", e1 != e4 );

	# type inference
	test_case( "type inference", x == e1 );
}

