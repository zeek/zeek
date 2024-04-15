# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
	{
	print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
	}


# Note: only global lists can be initialized with curly braces
# global lg1: list of string = { "curly", "braces" };
global lg1 = list("curly", "braces");

type R: record {
	a: bool &default=T;
};


event zeek_init()
{
	local l1: list of string = list( "test", "example" );
	local l2: list of string = list();
	local l3: list of string;
	local l4 = list( "type inference" );
	local l5 = list( 1, 2, 3 );
	local l6 = list( 10, 20, 30 );
	local l12 = list( T, F, T );
	local l13 = list( F, F, T );

	# Type inference tests

	test_case( "type inference", type_name(l4) == "list of string" );
	test_case( "type inference", type_name(l5) == "list of count" );
	test_case( "type inference", type_name(l12) == "list of bool" );

	# Test the size of each list

	test_case( "cardinality", |l1| == 2 );
	test_case( "cardinality", |l2| == 0 );
	test_case( "cardinality", |l3| == 0 );
	test_case( "cardinality", |l4| == 1 );
	test_case( "cardinality", |l5| == 3 );
	test_case( "cardinality", |l6| == 3 );

	# Test that lists use zero-based indexing

	test_case( "zero-based indexing", l1[0] == "test" && l5[0] == 1 );

	# Test iterating over each list

	local ct: count;
	ct = 0;
	for ( c in l1 )
	{
		if ( type_name(c) != "string" )
			print "Error: wrong index type";
		++ct;
	}
	test_case( "iterate over list", ct == 2 );

	ct = 0;
	for ( c in l2 )
	{
		++ct;
	}
	test_case( "iterate over list", ct == 0 );

	ct = 0;
	for ( c in lg1 )
	{
		++ct;
	}
	test_case( "iterate over list", ct == 2 );

	# Test adding elements to each list

	l1 += "added";
	test_case( "add element", |l1| == 3 );

	l2 += "another";
	test_case( "add element", |l2| == 1 );
	l2 += "test";
	test_case( "add element", |l2| == 2 );

	test_case( "access element", l2[0] == "another" );

	l3 += "foo";
	test_case( "add element", |l3| == 1 );
	test_case( "access element", l3[0] == "foo" );

	l4 += "local";
	test_case( "add element", |l4| == 2 );

	l5 += 77;
	test_case( "add element", |l5| == 4 );

	lg1 += "global";
	test_case( "add element", |lg1| == 3 );

	# Test removing elements of each list

	test_case( "removing front", --l1 == "test" );
	test_case( "removing front", --l1 == "example" );
	test_case( "removing front", --l1 == "added" );
	test_case( "removing front size", |l1| == 0 );

	# For a list-of-lists, += of an empty list should append it as
	# a single element, not all of its elements (= nothing gets appended).
	local l25: list of list of count;
	l25 += list();
	test_case( "+= of empty list", |l25| == 1 );

}
