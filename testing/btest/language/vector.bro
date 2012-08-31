# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


# Note: only global vectors can be initialized with curly braces
global v5: vector of string = { "curly", "braces" };

event bro_init()
{
	local v1: vector of string = vector( "test", "example" );
	local v2: vector of string = vector();
	local v3: vector of string;
	local v4 = vector( "type inference" );

	# Type inference test

	test_case( "type inference", type_name(v4) == "vector of string" );

	# Test the size of each vector

	test_case( "cardinality", |v1| == 2 );
	test_case( "cardinality", |v2| == 0 );
	test_case( "cardinality", |v3| == 0 );
	test_case( "cardinality", |v4| == 1 );
	test_case( "cardinality", |v5| == 2 );

	# Test iterating over each vector

	local ct: count;
	ct = 0;
	for ( c in v1 )
	{
		if ( type_name(c) != "int" )
			print "Error: wrong index type";
		if ( type_name(v1[c]) != "string" )
			print "Error: wrong vector type";
		++ct;
	}
	test_case( "iterate over vector", ct == 2 );

	ct = 0;
	for ( c in v2 )
	{
		++ct;
	}
	test_case( "iterate over vector", ct == 0 );

	ct = 0;
	for ( c in v5 )
	{
		++ct;
	}
	test_case( "iterate over vector", ct == 2 );

	# Test adding elements to each vector

	v1[2] = "added";
	test_case( "add element", |v1| == 3 );
	test_case( "access element", v1[2] == "added" );

	v2[0] = "another";
	test_case( "add element", |v2| == 1 );
	v2[1] = "test";
	test_case( "add element", |v2| == 2 );
	test_case( "access element", v2[0] == "another" );
	test_case( "access element", v2[1] == "test" );

	v3[0] = "foo";
	test_case( "add element", |v3| == 1 );
	test_case( "access element", v3[0] == "foo" );

	v4[1] = "local";
	test_case( "add element", |v4| == 2 );
	test_case( "access element", v4[1] == "local" );

	v5[2] = "global";
	test_case( "add element", |v5| == 3 );
	test_case( "access element", v5[2] == "global" );

	# Test overwriting elements of each vector

	v1[0] = "new1";
	test_case( "overwrite element", |v1| == 3 );
	test_case( "access element", v1[0] == "new1" );

	v2[1] = "new2";
	test_case( "overwrite element", |v2| == 2 );
	test_case( "access element", v2[0] == "another" );
	test_case( "access element", v2[1] == "new2" );

	v3[0] = "new3";
	test_case( "overwrite element", |v3| == 1 );
	test_case( "access element", v3[0] == "new3" );

	v4[0] = "new4";
	test_case( "overwrite element", |v4| == 2 );
	test_case( "access element", v4[0] == "new4" );

	v5[1] = "new5";
	test_case( "overwrite element", |v5| == 3 );
	test_case( "access element", v5[1] == "new5" );
}

