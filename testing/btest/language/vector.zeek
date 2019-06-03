# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


# Note: only global vectors can be initialized with curly braces
global vg1: vector of string = { "curly", "braces" };

event zeek_init()
{
	local v1: vector of string = vector( "test", "example" );
	local v2: vector of string = vector();
	local v3: vector of string;
	local v4 = vector( "type inference" );
	local v5 = vector( 1, 2, 3 );
	local v6 = vector( 10, 20, 30 );
	local v7 = v5 + v6;
	local v8 = v6 - v5;
	local v9 = v5 * v6;
	local v10 = v6 / v5;
	local v11 = v6 % v5;
	local v12 = vector( T, F, T );
	local v13 = vector( F, F, T );
	local v14 = v12 && v13;
	local v15 = v12 || v13;

	# Type inference tests

	test_case( "type inference", type_name(v4) == "vector of string" );
	test_case( "type inference", type_name(v5) == "vector of count" );
	test_case( "type inference", type_name(v12) == "vector of bool" );

	# Test the size of each vector

	test_case( "cardinality", |v1| == 2 );
	test_case( "cardinality", |v2| == 0 );
	test_case( "cardinality", |v3| == 0 );
	test_case( "cardinality", |v4| == 1 );
	test_case( "cardinality", |v5| == 3 );
	test_case( "cardinality", |v6| == 3 );
	test_case( "cardinality", |v7| == 3 );
	test_case( "cardinality", |v8| == 3 );
	test_case( "cardinality", |v9| == 3 );
	test_case( "cardinality", |v10| == 3 );
	test_case( "cardinality", |v11| == 3 );
	test_case( "cardinality", |v12| == 3 );
	test_case( "cardinality", |v13| == 3 );
	test_case( "cardinality", |v14| == 3 );
	test_case( "cardinality", |v15| == 3 );
	test_case( "cardinality", |vg1| == 2 );

	# Test that vectors use zero-based indexing

	test_case( "zero-based indexing", v1[0] == "test" && v5[0] == 1 );

	# Test iterating over each vector

	local ct: count;
	ct = 0;
	for ( c in v1 )
	{
		if ( type_name(c) != "count" )
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
	for ( c in vg1 )
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

	v5[3] = 77;
	test_case( "add element", |v5| == 4 );
	test_case( "access element", v5[3] == 77 );

	vg1[2] = "global";
	test_case( "add element", |vg1| == 3 );
	test_case( "access element", vg1[2] == "global" );

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

	v5[0] = 0;
	test_case( "overwrite element", |v5| == 4 );
	test_case( "access element", v5[0] == 0 );

	vg1[1] = "new5";
	test_case( "overwrite element", |vg1| == 3 );
	test_case( "access element", vg1[1] == "new5" );

	# Test increment/decrement operators

	++v5;
	test_case( "++ operator", |v5| == 4 && v5[0] == 1 && v5[1] == 3
			 && v5[2] == 4 && v5[3] == 78 );
	--v5;
	test_case( "-- operator", |v5| == 4 && v5[0] == 0 && v5[1] == 2
			 && v5[2] == 3 && v5[3] == 77 );

	# Test +,-,*,/,% of two vectors

	test_case( "+ operator", v7[0] == 11 && v7[1] == 22 && v7[2] == 33 );
	test_case( "- operator", v8[0] == 9 && v8[1] == 18 && v8[2] == 27 );
	test_case( "* operator", v9[0] == 10 && v9[1] == 40 && v9[2] == 90 );
	test_case( "/ operator", v10[0] == 10 && v10[1] == 10 && v10[2] == 10 );
	test_case( "% operator", v11[0] == 0 && v11[1] == 0 && v11[2] == 0 );

	# Test &&,|| of two vectors

	test_case( "&& operator", v14[0] == F && v14[1] == F && v14[2] == T );
	test_case( "|| operator", v15[0] == T && v15[1] == F && v15[2] == T );

	# Test += operator.
	local v16 = v6;
	v16 += 40;
	test_case( "+= operator", all_set(v16 == vector( 10, 20, 30, 40 )) );

}

