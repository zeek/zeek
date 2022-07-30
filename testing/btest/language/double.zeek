# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

global d1: double = 3;
global d2: double = +3;
global d3: double = 3.;
global d4: double = 3.0;
global d5: double = +3.0;
global d6: double = 3e0;
global d7: double = 3E0;
global d8: double = 3e+0;
global d9: double = 3e-0;
global d10: double = 3.0e0;
global d11: double = +3.0e0;
global d12: double = +3.0e+0;
global d13: double = +3.0E+0;
global d14: double = +3.0E-0;
global d15: double = .03E+2;
global d16: double = .03E2;
global d17: double = 3.0001;
global d18: double = -3.0001;
global d19: double = 1.7976931348623157e308;  # maximum allowed value
global d20 = 7.0;
global d21 = 7e0;
global d22 = 7e+1;

event zeek_init()
{
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

	# Printing small numbers: default precision is 6 with values smaller than
	# 10^-6 rendered in scientific notation, preserving exact floating point
	# representation.
	print "";
	print 0.0000000000005;
	print 0.000000000005;
	print 0.00000000005;
	print 0.0000000005;
	print 0.000000005;
	print 0.00000005;
	print 0.0000005;
	print "";
	print 0.000005;
	print 0.00005;
	print 0.0005;
	print 0.005;
	print 0.05;
	print 0.5;
	print 5.0;
	print "";
	print 0.0000000000001;
	print 0.000000000001;
	print 0.00000000001;
	print 0.0000000001;
	print 0.000000001;
	print 0.00000001;
	print 0.0000001;
	print "";
	print 0.000001;
	print 0.00001;
	print 0.0001;
	print 0.001;
	print 0.01;
	print 0.1;
	print 1.0;
}

