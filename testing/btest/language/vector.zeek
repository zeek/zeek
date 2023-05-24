# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


# Note: only global vectors can be initialized with curly braces
global vg1: vector of string = { "curly", "braces" };

type R: record {
	a: bool &default=T;
};


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
	local v18 = v12 ? v5 : v6;

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

	v5[10] = 10;
	test_case( "add above a hole", |v5| == 11 );
	test_case( "in operator for non-hole", 3 in v5 );
	test_case( "in operator for hole", 4 !in v5 );
	test_case( "in operator for edge", |v5|-1 in v5 );
	test_case( "in operator for out of range", 44 !in v5 );

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
	test_case( "overwrite element", |v5| == 11 );
	test_case( "access element", v5[0] == 0 );

	vg1[1] = "new5";
	test_case( "overwrite element", |vg1| == 3 );
	test_case( "access element", vg1[1] == "new5" );

	# Test +,-,*,/,% of two vectors

	test_case( "+ operator", v7[0] == 11 && v7[1] == 22 && v7[2] == 33 );
	test_case( "- operator", v8[0] == 9 && v8[1] == 18 && v8[2] == 27 );
	test_case( "* operator", v9[0] == 10 && v9[1] == 40 && v9[2] == 90 );
	test_case( "/ operator", v10[0] == 10 && v10[1] == 10 && v10[2] == 10 );
	test_case( "% operator", v11[0] == 0 && v11[1] == 0 && v11[2] == 0 );

	local vs1: vector of string = vector( "foo", "bar" );
	local vs2: vector of string = vector( "xxx", "yyy" );
	local vs3: vector of string = vector( "xxx", "bar" );

	local vss = vs1 + vs2;
	test_case( "+ operator [string]", vss[0] == "fooxxx" && vss[1] == "baryyy" );

	local vss3 = (vs1 == vs3);
	test_case( "== operator [string]", vss3[0] == F && vss3[1] == T );

	# Test &&,|| of two vectors

	test_case( "&& operator", v14[0] == F && v14[1] == F && v14[2] == T );
	test_case( "|| operator", v15[0] == T && v15[1] == F && v15[2] == T );

	# Test += operator.
	local v16 = v6;
	v16 += 40;
	test_case( "+= operator", all_set(v16 == vector( 10, 20, 30, 40 )) );

	# Slicing tests.
	local v17 = vector( 1, 2, 3, 4, 5 );
	test_case( "slicing", all_set(v17[0:2] == vector( 1, 2 )) );
	test_case( "slicing", all_set(v17[-3:-1] == vector( 3, 4 )) );
	test_case( "slicing", all_set(v17[:2] == vector( 1, 2 )) );
	test_case( "slicing", all_set(v17[2:] == vector( 3, 4, 5 )) );
	test_case( "slicing", all_set(v17[:] == v17) );
	v17[0:1] = vector(6);
	test_case( "slicing assignment", all_set(v17 == vector(6, 2, 3, 4, 5)) );
	v17[2:4] = vector(7, 8);
	test_case( "slicing assignment", all_set(v17 == vector(6, 2, 7, 8, 5)) );
	v17[2:4] = vector(9, 10, 11);
	test_case( "slicing assignment grow", all_set(v17 == vector(6, 2, 9, 10, 11, 5)) );
	v17[2:5] = vector(9);
	test_case( "slicing assignment shrink", all_set(v17 == vector(6, 2, 9, 5)) );

	# Test boolean ? operator.
	test_case( "? operator", all_set(v18 == vector(1, 20, 3)) );

	# Test copying of a vector with holes, as this used to crash.
	local v19 = copy(v5);
	test_case( "copy of a vector with holes", |v5| == |v19| );
	# Even after removing some elements at the end, any trailing holes should
	# be preserved after copying;
	v5[6:] = vector();
	local v20 = copy(v5);
	print "copy of a vector with trailing holes", v5, v20;

	local v21 = vector(R(), R());
	v21[4] = R();
	print "hole in vector of managed types", |v21|, v21;
	v21[3:] = vector();
	print "hole in vector of managed types after replacing slice", |v21|, v21;

	# Test << and >> operators.
	local four_ones = vector(1, 1, 1, 1);
	local v22 = v6 << four_ones;
	local v23 = v6 >> four_ones;
	test_case( "left shift", all_set(v22 == vector(20, 40, 60, 80)) );
	test_case( "right shift", all_set(v23 == vector(5, 10, 15, 20)) );

	# negative indices
	local v24 = vector( 1, 2, 3, 4, 5 );
	test_case( "negative index", v24[-1] == 5 );
	test_case( "negative index", v24[-3] == 3 );

}
