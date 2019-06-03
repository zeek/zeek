# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

function approx_equal(x: double, y: double): bool
	{
	# return T if x and y are approximately equal, and F otherwise
	return |(x - y)/x| < 1e-6 ? T : F;
	}

event zeek_init()
{
	# Constants without space and no letter "s"

	local in11: interval = 2usec;
	local in12: interval = 2msec;
	local in13: interval = 120sec;
	local in14: interval = 2min;
	local in15: interval = -2hr;
	local in16: interval = 2.5day;

	# Constants with space and no letter "s"

	local in21: interval = 2 usec;
	local in22: interval = 2 msec;
	local in23: interval = 120 sec;
	local in24: interval = 2 min;
	local in25: interval = -2 hr;
	local in26: interval = 2.5 day;

	# Constants with space and letter "s"

	local in31: interval = 2 usecs;
	local in32: interval = 2 msecs;
	local in33: interval = 1.2e2 secs;
	local in34: interval = 2 mins;
	local in35: interval = -2 hrs;
	local in36: interval = 2.5 days;

	# Type inference

	local in41 = 2 usec;
	local in42 = 2.1usec;
	local in43 = 3usecs;

	# Type inference tests

	test_case( "type inference", type_name(in41) == "interval" );
	test_case( "type inference", type_name(in42) == "interval" );
	test_case( "type inference", type_name(in43) == "interval" );

	# Test various constant representations

	test_case( "optional space", in11 == in21 );
	test_case( "plural/singular interval are same", in11 == in31 );

	# Operator tests

	test_case( "different units with same numeric value", in11 != in12 );
	test_case( "compare different time units", in13 == in34 );
	test_case( "compare different time units", in13 <= in34 );
	test_case( "compare different time units", in13 >= in34 );
	test_case( "compare different time units", in13 < in36 );
	test_case( "compare different time units", in13 <= in36 );
	test_case( "compare different time units", in13 > in35 );
	test_case( "compare different time units", in13 >= in35 );
	test_case( "add different time units", in13 + in14 == 4min );
	test_case( "subtract different time units", in24 - in23 == 0sec );
	test_case( "absolute value", |in25| == 2.0*3600 );
	test_case( "absolute value", |in36| == 2.5*86400 );
	test_case( "absolute value", |5sec - 9sec| == 4.0 );
	in34 += 2hr;
	test_case( "assignment operator", in34 == 122min );
	in34 -= 2hr;
	test_case( "assignment operator", in34 == 2min );
	test_case( "multiplication operator", in33*2 == 4min );
	test_case( "division operator", in35/2 == -1hr );
	test_case( "division operator", approx_equal(in32/in31, 1e3) );

	# Test relative size of each interval unit

	test_case( "relative size of units", approx_equal(1msec/1usec, 1000) );
	test_case( "relative size of units", approx_equal(1sec/1msec, 1000) );
	test_case( "relative size of units", approx_equal(1min/1sec, 60) );
	test_case( "relative size of units", approx_equal(1hr/1min, 60) );
	test_case( "relative size of units", approx_equal(1day/1hr, 24) );

}

