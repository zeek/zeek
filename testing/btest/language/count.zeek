# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event zeek_init()
{
	local c1: count = 0;
	local c2: count = 5;
	local c3: count = 0xFF;
	local c4: count = 255;
	local c5: count = 18446744073709551615;  # maximum allowed value
	local c6: count = 0xffffffffffffffff;    # maximum allowed value
	local c7: counter = 5;
	local c8 = 1;

	# Type inference test

	test_case( "type inference", type_name(c8) == "count" );

	# Counter alias test

	test_case( "counter alias", c2 == c7 );

	# Test various constant representations

	test_case( "hexadecimal", c3 == c4 );

	# Operator tests

	test_case( "inequality operator", c1 != c2 );
	test_case( "relational operator", c1 < c2 );
	test_case( "relational operator", c1 <= c2 );
	test_case( "relational operator", c2 > c1 );
	test_case( "relational operator", c2 >= c1 );
	test_case( "absolute value", |c1| == 0 );
	test_case( "absolute value", |c2| == 5 );
	test_case( "pre-increment operator", ++c2 == 6 );
	test_case( "pre-decrement operator", --c2 == 5 );
	test_case( "modulus operator", c2%2 == 1 );
	test_case( "division operator", c2/2 == 2 );
	c2 += 3;
	test_case( "assignment operator", c2 == 8 );
	c2 -= 2;
	test_case( "assignment operator", c2 == 6 );
	test_case( "bitwise and", c2 & 0x4 == 0x4 );
	test_case( "bitwise and", c4 & 0x4 == 0x4 );
	test_case( "bitwise and", c8 & 0x4 == 0x0 );
	test_case( "bitwise or", c2 | 0x4 == c2 );
	test_case( "bitwise or", c4 | 0x4 == c4 );
	test_case( "bitwise or", c8 | 0x4 == c7 );
	test_case( "bitwise xor", c7 ^ 0x4 == c8 );
	test_case( "bitwise xor", c4 ^ 0x4 == 251 );
	test_case( "bitwise xor", c8 ^ 0x4 == c7 );
	test_case( "bitwise complement", ~c6 == 0 );
	test_case( "bitwise complement", ~~c4 == c4 );

	# Max. value tests

	local str1 = fmt("max count value = %d", c5);
	test_case( str1, str1 == "max count value = 18446744073709551615" );
	local str2 = fmt("max count value = %d", c6);
	test_case( str2, str2 == "max count value = 18446744073709551615" );

}

