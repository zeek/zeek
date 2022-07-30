# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

function approx_equal(x: double, y: double): bool
	{
	# return T if x and y are approximately equal, and F otherwise
	return |(x - y)/x| < 1e-6 ? T : F;
	}

# Constants without space and no letter "s"
global in11: interval = 2usec;
global in12: interval = 2msec;
global in13: interval = 120sec;
global in14: interval = 2min;
global in15: interval = -2hr;
global in16: interval = 2.5day;

# Constants with space and no letter "s"
global in21: interval = 2 usec;
global in22: interval = 2 msec;
global in23: interval = 120 sec;
global in24: interval = 2 min;
global in25: interval = -2 hr;
global in26: interval = 2.5 day;

# Constants with space and letter "s"

global in31: interval = 2 usecs;
global in32: interval = 2 msecs;
global in33: interval = 1.2e2 secs;
global in34: interval = 2 mins;
global in35: interval = -2 hrs;
global in36: interval = 2.5 days;

# Type inference

global in41 = 2 usec;
global in42 = 2.1usec;
global in43 = 3usecs;

event zeek_init()
{
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

