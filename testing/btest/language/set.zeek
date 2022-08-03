# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }


# Note: only global sets can be initialized with curly braces
global sg1: set[string] = { "curly", "braces" };
global sg2: set[port, string, bool] = { [10/udp, "curly", F],
		[11/udp, "braces", T] };
global sg3 = { "more", "curly", "braces" };

function basic_functionality()
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


	local a = set(1,5,7,9,8,14);
	local b = set(1,7,9,2);

	local a_plus_b = set(1,2,5,7,9,8,14);
	local a_also_b = set(1,7,9);
	local a_sans_b = set(5,8,14);
	local b_sans_a = set(2);

	local a_or_b = a | b;
	local a_and_b = a & b;
	local b_and_a = b & a;

	test_case( "union", a_or_b == a_plus_b );
	test_case( "intersection", a_and_b == a_also_b );
	test_case( "intersection", b_and_a == a_also_b );
	test_case( "difference", a - b == a_sans_b );
	test_case( "difference", b - a == b_sans_a );

	test_case( "union/inter.", |b & set(1,7,9,2)| == |b | set(1,7,2,9)| );
	test_case( "relational", |b & a_or_b| == |b| && |b| < |a_or_b| );
	test_case( "relational", b < a_or_b && a < a_or_b && a_or_b > a_and_b );

	test_case( "subset", b < a );
	test_case( "subset", a < b );
	test_case( "subset", b < (a | set(2)) );
	test_case( "superset", b > a );
	test_case( "superset", b > (a | set(2)) );
	test_case( "superset", b | set(8, 14, 5) > (a | set(2)) );
	test_case( "superset", b | set(8, 14, 99, 5) > (a | set(2)) );

	test_case( "non-ordering", (a <= b) || (a >= b) );
	test_case( "non-ordering", (a <= a_or_b) && (a_or_b >= b) );

	test_case( "superset", (b | set(14, 5)) > a - set(8) );
	test_case( "superset", (b | set(14)) > a - set(8) );
	test_case( "superset", (b | set(14)) > a - set(8,5) );
	test_case( "superset", b >= a - set(5,8,14) );
	test_case( "superset", b > a - set(5,8,14) );
	test_case( "superset", (b - set(2)) > a - set(5,8,14) );
	test_case( "equality", a == a | set(5) );
	test_case( "equality", a == a | set(5,11) );
	test_case( "non-equality", a != a | set(5,11) );
	test_case( "equality", a == a | set(5,11) );

	test_case( "magnitude", |a_and_b| == |a_or_b|);
}

function complex_index_types()
{
	# Initialization
	local s1: set[table[string] of string] = { table(["k1"] = "v1") };

	# Adding a member
	add s1[table(["k2"] = "v2")];

	# Various checks, including membership test
	test_case( "table index size", |s1| == 2 );
	test_case( "table index membership", table(["k2"] = "v2") in s1 );
	test_case( "table index non-membership", table(["k2"] = "v3") !in s1 );

	# Member deletion
	delete s1[table(["k1"] = "v1")];
	test_case( "table index reduced size", |s1| == 1 );

	# Iteration
	for ( ti in s1 )
		{
		test_case( "table index iteration", to_json(ti) == to_json(table(["k2"] = "v2")) );
		break;
		}

	# As above, for other index types
	local s2: set[vector of string] = { vector("v1", "v2") };

	add s2[vector("v3", "v4")];
	test_case( "vector index size", |s2| == 2 );
	test_case( "vector index membership", vector("v3", "v4") in s2 );
	test_case( "vector index non-membership", vector("v4", "v5") !in s2 );

	delete s2[vector("v1", "v2")];
	test_case( "vector index reduced size", |s2| == 1 );

	for ( vi in s2 )
		{
		test_case( "vector index iteration", to_json(vi) == to_json(vector("v3", "v4")) );
		break;
		}

	local s3: set[set[string]] = { set("s1", "s2") };

	add s3[set("s3", "s4")];
	test_case( "set index size", |s3| == 2 );
	test_case( "set index membership", set("s3", "s4") in s3 );
	test_case( "set index non-membership", set("s4", "s5") !in s3 );

	delete s3[set("s1", "s2")];
	test_case( "set index reduced size", |s3| == 1 );

	for ( si in s3 )
		{
		test_case( "set index iteration", to_json(si) == to_json(set("s3", "s4")) );
		break;
		}

	local s4: set[pattern] = { /pat1/ };

	add s4[/pat2/];
	test_case( "pattern index size", |s4| == 2 );
	test_case( "pattern index membership", /pat2/ in s4 );
	test_case( "pattern index non-membership", /pat3/ !in s4 );

	delete s4[/pat1/];
	test_case( "pattern index reduced size", |s4| == 1 );

	for ( pi in s4 )
		{
		test_case( "pattern index iteration", to_json(pi) == to_json(/pat2/) );
		break;
		}
}

event zeek_init()
{
	basic_functionality();
	complex_index_types();
}
