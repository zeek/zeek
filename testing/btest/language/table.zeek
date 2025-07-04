# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }

# Note: only global tables can be initialized with curly braces when the table
# type is not explicitly specified
global tg1 = { [1] = "type", [2] = "inference", [3] = "test" };

function basic_functionality()
{
	local t1: table[count] of string = table( [5] = "test", [0] = "example" );
	local t2: table[count] of string = table();
	local t3: table[count] of string;
	local t4 = table( [1] = "type inference" );
	local t5: table[count] of string = { [1] = "curly", [3] = "braces" };
	local t6: table[port, string, bool] of string = table(
			 [1/tcp, "test", T] = "test1",
			 [2/tcp, "example", F] = "test2" );
	local t7: table[port, string, bool] of string = table();
	local t8: table[port, string, bool] of string;
	local t9 = table( [8/tcp, "type inference", T] = "this" );
	local t10: table[port, string, bool] of string = { 
		[10/udp, "curly", F] = "first",
		[11/udp, "braces", T] = "second" };
	local t11: table[conn_id, bool] of count = {
	    [ [$orig_h=1.1.1.1, $orig_p=1234/tcp,
	       $resp_h=2.2.2.2, $resp_p=4321/tcp, $ctx=[]], T ] = 42 };

	# Type inference tests

	test_case( "type inference", type_name(t4) == "table[count] of string" );
	test_case( "type inference", type_name(t9) == "table[port,string,bool] of string" );
	test_case( "type inference", type_name(tg1) == "table[count] of string" );

	# Test the size of each table

	test_case( "cardinality", |t1| == 2 );
	test_case( "cardinality", |t2| == 0 );
	test_case( "cardinality", |t3| == 0 );
	test_case( "cardinality", |t4| == 1 );
	test_case( "cardinality", |t5| == 2 );
	test_case( "cardinality", |t6| == 2 );
	test_case( "cardinality", |t7| == 0 );
	test_case( "cardinality", |t8| == 0 );
	test_case( "cardinality", |t9| == 1 );
	test_case( "cardinality", |t10| == 2 );
	test_case( "cardinality", |t11| == 1 );
	test_case( "cardinality", |tg1| == 3 );

	# Test iterating over each table

	local ct: count;
	ct = 0;
	for ( c in t1 )
	{
		if ( type_name(c) != "count" )
			print "Error: wrong index type";
		if ( type_name(t1[c]) != "string" )
			print "Error: wrong table type";
		++ct;
	}
	test_case( "iterate over table", ct == 2 );

	ct = 0;
	for ( c in t2 )
	{
		++ct;
	}
	test_case( "iterate over table", ct == 0 );

	ct = 0;
	for ( c in t3 )
	{
		++ct;
	}
	test_case( "iterate over table", ct == 0 );

	ct = 0;
	for ( [c1, c2, c3] in t6 )
	{
		++ct;
	}
	test_case( "iterate over table", ct == 2 );

	ct = 0;
	for ( [c1, c2, c3] in t7 )
	{
		++ct;
	}
	test_case( "iterate over table", ct == 0 );

	# Test overwriting elements in each table (Note: cannot overwrite
	# elements in tables of multiple types)

	t1[5] = "overwrite";
	test_case( "overwrite element", |t1| == 2 && t1[5] == "overwrite" );
 
	# Test adding elements to each table (Note: cannot add elements to
	# tables of multiple types)

	t1[1] = "added";
	test_case( "add element", |t1| == 3 );
	test_case( "in operator", 1 in t1 );

	t2[11] = "another";
	test_case( "add element", |t2| == 1 );
	t2[0] = "test";
	test_case( "add element", |t2| == 2 );
	test_case( "in operator", 11 in t2 );
	test_case( "in operator", 0 in t2 );

	t3[3] = "foo";
	test_case( "add element", |t3| == 1 );
	test_case( "in operator", 3 in t3 );

	t4[4] = "local";
	test_case( "add element", |t4| == 2 );
	test_case( "in operator", 4 in t4 );

	t5[10] = "local2";
	test_case( "add element", |t5| == 3 );
	test_case( "in operator", 10 in t5 );

	local cid = [$orig_h=1.1.1.1, $orig_p=1234/tcp,
	             $resp_h=2.2.2.2, $resp_p=4321/tcp, $ctx=[]];
	t11[[$orig_h=[::1], $orig_p=3/tcp, $resp_h=[::2], $resp_p=3/tcp, $ctx=[]], F] = 3;
	test_case( "composite index add element", |t11| == 2 );
	test_case( "composite index in operator", [cid, T] in t11 );
	test_case( "composite index in operator", [[$orig_h=[::1], $orig_p=3/tcp, $resp_h=[::2], $resp_p=3/tcp, $ctx=[]], F] in t11 );

	# Test removing elements from each table (Note: cannot remove elements
	# from tables of multiple types)

	delete t1[0];
	delete t1[17];  # element does not exist (nothing happens)
	test_case( "remove element", |t1| == 2 );
	test_case( "!in operator", 0 !in t1 );

	delete t2[0];
	test_case( "remove element", |t2| == 1 );
	test_case( "!in operator", 0 !in t2 );

	delete t3[3];
	test_case( "remove element", |t3| == 0 );
	test_case( "!in operator", 3 !in t3 );

	delete t4[1];
	test_case( "remove element", |t4| == 1 );
	test_case( "!in operator", 1 !in t4 );

	delete t5[1];
	test_case( "remove element", |t5| == 2 );
	test_case( "!in operator", 1 !in t5 );

	delete t11[cid, T];
	test_case( "remove element", |t11| == 1 );
	test_case( "!in operator", [cid, T] !in t11 );
}

type tss_table: table[table[string] of string] of string;

function complex_index_type_table()
{
	# Initialization
	local t: tss_table = {
		[table(["k1"] = "v1")] = "res1"
	};

	# Adding a member
	t[table(["k2"] = "v2")] = "res2";

	# Various checks, including membership test and lookup
	test_case( "table index size", |t| == 2 );
	test_case( "table index membership", table(["k2"] = "v2") in t );
	test_case( "table index non-membership", table(["k2"] = "v3") !in t );
	test_case( "table index lookup", t[table(["k2"] = "v2")] == "res2" );

	# Member deletion
	delete t[table(["k1"] = "v1")];
	test_case( "table index reduced size", |t| == 1 );

	# Iteration
	for ( ti in t )
		{
		test_case( "table index iteration", to_json(ti) == to_json(table(["k2"] = "v2")) );
		break;
		}

	# JSON serialize/unserialize
	local fjr = from_json(to_json(t), tss_table);
	test_case( "table index JSON roundtrip success", fjr$valid );
	test_case( "table index JSON roundtrip correct", to_json(t) == to_json(fjr$v) );
}

type vs_table: table[vector of string] of string;

function complex_index_type_vector()
{
	local t: vs_table = {
		[vector("v1", "v2")] = "res1"
	};

	t[vector("v3", "v4")] = "res2";
	test_case( "vector index size", |t| == 2 );
	test_case( "vector index membership", vector("v3", "v4") in t );
	test_case( "vector index non-membership", vector("v4", "v5") !in t );
	test_case( "vector index lookup", t[vector("v3", "v4")] == "res2" );

	delete t[vector("v1", "v2")];
	test_case( "vector index reduced size", |t| == 1 );

	for ( vi in t )
		{
		test_case( "vector index iteration", to_json(vi) == to_json(vector("v3", "v4")) );
		break;
		}

	local fjr = from_json(to_json(t), vs_table);
	test_case( "vector index JSON roundtrip success", fjr$valid );
	test_case( "vector index JSON roundtrip", to_json(t) == to_json(fjr$v) );
}

type ss_table: table[set[string]] of string;

function complex_index_type_set()
{
	local t: ss_table = {
		[set("s1", "s2")] = "res1"
	};

	t[set("s3", "s4")] = "res2";
	test_case( "set index size", |t| == 2 );
	test_case( "set index membership", set("s3", "s4") in t );
	test_case( "set index non-membership", set("s4", "s5") !in t );
	test_case( "set index lookup", t[set("s3", "s4")] == "res2" );

	delete t[set("s1", "s2")];
	test_case( "set index reduced size", |t| == 1 );

	for ( si in t )
		{
		test_case( "set index iteration", to_json(si) == to_json(set("s3", "s4")) );
		break;
		}

	local fjr = from_json(to_json(t), ss_table);
	test_case( "set index JSON roundtrip success", fjr$valid );
	test_case( "set index JSON roundtrip", to_json(t) == to_json(fjr$v) );
}

type tp_table: table[pattern] of string;

function complex_index_type_pattern()
{
	local t: tp_table = {
		[/pat1/] = "res1"
	};

	t[/pat2/] = "res2";
	test_case( "pattern index size", |t| == 2 );
	test_case( "pattern index membership", /pat2/ in t );
	test_case( "pattern index non-membership", /pat3/ !in t );
	test_case( "pattern index lookup", t[/pat2/] == "res2" );

	delete t[/pat1/];
	test_case( "pattern index reduced size", |t| == 1 );

	for ( pi in t )
		{
		test_case( "pattern index iteration", to_json(pi) == to_json(/pat2/) );
		break;
		}

	local fjr = from_json(to_json(t), tp_table);
	test_case( "pattern index JSON roundtrip success", fjr$valid );
	test_case( "pattern index JSON roundtrip", to_json(t) == to_json(fjr$v) );
}

event zeek_init()
{
	basic_functionality();
	complex_index_type_table();
	complex_index_type_vector();
	complex_index_type_set();
	complex_index_type_pattern();
}
