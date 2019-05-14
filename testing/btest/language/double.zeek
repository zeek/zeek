# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


event zeek_init()
{
	local d1: double = 3;
	local d2: double = +3;
	local d3: double = 3.;
	local d4: double = 3.0;
	local d5: double = +3.0;
	local d6: double = 3e0;
	local d7: double = 3E0;
	local d8: double = 3e+0;
	local d9: double = 3e-0;
	local d10: double = 3.0e0;
	local d11: double = +3.0e0;
	local d12: double = +3.0e+0;
	local d13: double = +3.0E+0;
	local d14: double = +3.0E-0;
	local d15: double = .03E+2;
	local d16: double = .03E2;
	local d17: double = 3.0001;
	local d18: double = -3.0001;
	local d19: double = 1.7976931348623157e308;  # maximum allowed value
	local d20 = 7.0;
	local d21 = 7e0;
	local d22 = 7e+1;

	# Type inference tests

	test_case( "type inference", type_name(d20) == "double" );
	test_case( "type inference", type_name(d21) == "double" );
	test_case( "type inference", type_name(d22) == "double" );

	# Test various constant representations

	test_case( "double representations", d1 == d2 );
	test_case( "double representations", d1 == d3 );
	test_case( "double representations", d1 == d4 );
	test_case( "double representations", d1 == d5 );
	test_case( "double representations", d1 == d6 );
	test_case( "double representations", d1 == d7 );
	test_case( "double representations", d1 == d8 );
	test_case( "double representations", d1 == d9 );
	test_case( "double representations", d1 == d10 );
	test_case( "double representations", d1 == d11 );
	test_case( "double representations", d1 == d12 );
	test_case( "double representations", d1 == d13 );
	test_case( "double representations", d1 == d14 );
	test_case( "double representations", d1 == d15 );
	test_case( "double representations", d1 == d16 );

	# Operator tests

	test_case( "inequality operator", d18 != d17 );
	test_case( "absolute value", |d18| == d17 );
	d4 += 2;
	test_case( "assignment operator", d4 == 5.0 );
	d4 -= 3;
	test_case( "assignment operator", d4 == 2.0 );
	test_case( "relational operator", d4 <= d3 );
	test_case( "relational operator", d4 < d3 );
	test_case( "relational operator", d17 >= d3 );
	test_case( "relational operator", d17 > d3 );
	test_case( "division operator", d3/2 == 1.5 );

	# Max. value test

	local str1 = fmt("max double value = %.16e", d19);
	test_case( str1, str1 == "max double value = 1.7976931348623157e+308" );

}

