# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


# Note: only global sets can be initialized with curly braces
global sg1: set[string] = { "curly", "braces" };
global sg2: set[port, string, bool] = { [10/udp, "curly", F],
		[11/udp, "braces", T] };
global sg3 = { "more", "curly", "braces" };

event bro_init()
{
	local s1: set[string] = set( "test", "example" );
	local s2: set[string] = set();
	local s3: set[string];
	local s4 = set( "type inference" );
	local s5: set[port, string, bool] = set( [1/tcp, "test", T],
			 [2/tcp, "example", F] );
	local s6: set[port, string, bool] = set();
	local s7: set[port, string, bool];
	local s8 = set( [8/tcp, "type inference", T] );

	# Type inference tests

	test_case( "type inference", type_name(s4) == "set[string]" );
	test_case( "type inference", type_name(s8) == "set[port,string,bool]" );
	test_case( "type inference", type_name(sg3) == "set[string]" );

	# Test the size of each set

	test_case( "cardinality", |s1| == 2 );
	test_case( "cardinality", |s2| == 0 );
	test_case( "cardinality", |s3| == 0 );
	test_case( "cardinality", |s4| == 1 );
	test_case( "cardinality", |s5| == 2 );
	test_case( "cardinality", |s6| == 0 );
	test_case( "cardinality", |s7| == 0 );
	test_case( "cardinality", |s8| == 1 );
	test_case( "cardinality", |sg1| == 2 );
	test_case( "cardinality", |sg2| == 2 );
	test_case( "cardinality", |sg3| == 3 );

	# Test iterating over each set

	local ct: count;
	ct = 0;
	for ( c in s1 )
	{
		if ( type_name(c) != "string" )
			print "Error: wrong set element type";
		++ct;
	}
	test_case( "iterate over set", ct == 2 );

	ct = 0;
	for ( c in s2 )
	{
		++ct;
	}
	test_case( "iterate over set", ct == 0 );

	ct = 0;
	for ( [c1,c2,c3] in s5 )
	{
		++ct;
	}
	test_case( "iterate over set", ct == 2 );

	ct = 0;
	for ( [c1,c2,c3] in sg2 )
	{
		++ct;
	}
	test_case( "iterate over set", ct == 2 );

	# Test adding elements to each set (Note: cannot add elements to sets
	# of multiple types)

	add s1["added"];
	add s1["added"];  # element already exists (nothing happens)
	test_case( "add element", |s1| == 3 );
	test_case( "in operator", "added" in s1 );

	add s2["another"];
	test_case( "add element", |s2| == 1 );
	add s2["test"];
	test_case( "add element", |s2| == 2 );
	test_case( "in operator", "another" in s2 );
	test_case( "in operator", "test" in s2 );

	add s3["foo"];
	test_case( "add element", |s3| == 1 );
	test_case( "in operator", "foo" in s3 );

	add s4["local"];
	test_case( "add element", |s4| == 2 );
	test_case( "in operator", "local" in s4 );

	add sg1["global"];
	test_case( "add element", |sg1| == 3 );
	test_case( "in operator", "global" in sg1 );

	add sg3["more global"];
	test_case( "add element", |sg3| == 4 );
	test_case( "in operator", "more global" in sg3 );

	# Test removing elements from each set (Note: cannot remove elements
	# from sets of multiple types)

	delete s1["test"];
	delete s1["foobar"];  # element does not exist (nothing happens)
	test_case( "remove element", |s1| == 2 );
	test_case( "!in operator", "test" !in s1 );

	delete s2["test"];
	test_case( "remove element", |s2| == 1 );
	test_case( "!in operator", "test" !in s2 );

	delete s3["foo"];
	test_case( "remove element", |s3| == 0 );
	test_case( "!in operator", "foo" !in s3 );

	delete s4["type inference"];
	test_case( "remove element", |s4| == 1 );
	test_case( "!in operator", "type inference" !in s4 );

	delete sg1["braces"];
	test_case( "remove element", |sg1| == 2 );
	test_case( "!in operator", "braces" !in sg1 );

	delete sg3["curly"];
	test_case( "remove element", |sg3| == 3 );
	test_case( "!in operator", "curly" !in sg3 );
}

