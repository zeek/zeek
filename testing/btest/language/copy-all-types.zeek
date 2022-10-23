# Note: opaque types in separate test
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyEnum: enum { ENUMME };

type InnerTestRecord: record {
	a: string;
};

type TestRecord: record {
	s1: string;
	s2: string;
	i1: InnerTestRecord;
	i2: InnerTestRecord &optional;
	donotset: InnerTestRecord &optional;
	def: count &default=5;
};

function join_count_set(ss: set[count], j: string): string
	{
	local output="";
	local i=0;
	for ( s in ss )
		{
		if ( i > 0 )
			output = cat(output, j);

		output = cat(output, s);
		++i;
		}
	return output;
	}

function do_format(i: any): any
	{
	local tpe = type_name(i);

	switch ( tpe )
		{
		case "set[count]":
			return join_count_set(i, ",");
		case "table[string] of string":
			local cast: table[string] of string = i;
			local vout: vector of string = vector();
			for ( el in cast )
				{
				vout += cat(el, "=", cast[el]);
				}
			return join_string_vec(vout, ";");
		}
	return i;
	}

function check(o1: any, o2: any, equal: bool, expect_same: bool)
	{
	local expect_msg = (equal ? "ok" : "FAIL0");
	local same = same_object(o1, o2);

	if ( expect_same && ! same )
		expect_msg = "FAIL1";

	if ( ! expect_same && same )
		expect_msg = "FAIL2";

	print fmt("orig=%s (%s) clone=%s (%s) equal=%s same_object=%s (%s)", do_format(o1), type_name(o1), do_format(o2), type_name(o2), equal, same, expect_msg);
	}

function check_vector_equal(a: vector of count, b: vector of count): bool
	{
	if ( |a| != |b| )
		return F;

	for ( i in a )
		{
		if ( a[i] != b[i] )
			return F;
		}

	return T;
	}

function check_string_table_equal(a: table[string] of string, b: table[string] of string): bool
	{
	if ( |a| != |b| )
		return F;

	for ( i in a )
		{
		if ( a[i] != b[i] )
			return F;
		}

	return T;
	}

function compare_otr(a: TestRecord, b: TestRecord): bool
	{
	if ( a$s1 != b$s1 )
		return F;
	if ( a$s2 != b$s2 )
		return F;
	if ( a$i1$a != b$i1$a )
		return F;
	if ( a$i2$a != b$i2$a )
		return F;

	if ( same_object(a$i1, b$i1) )
		return F;
	if ( same_object(a$i2, b$i2) )
		return F;

	# check that we restroe that i1 & i2 point to same object
	if ( ! same_object(a$i1, a$i2) )
		return F;
	if ( ! same_object(b$i1, b$i2) )
		return F;

	if ( a$def != b$def )
		return F;

	return T;
	}


event zeek_init()
	{
	local i1 = -42;
	local i2 = copy(i1);
	check(i1, i2, i1 == i2, T);

	local c1 : count = 42;
	local c2 = copy(c1);
	check(c1, c2, c1 == c2, T);

	local a1 = 127.0.0.1;
	local a2 = copy(a1);
	check(a1, a2, a1 == a2, T);

	local p1 = 42/tcp;
	local p2 = copy(p1);
	check(p1, p2, p1 == p2, T);

	local sn1 = 127.0.0.1/24;
	local sn2 = copy(sn1);
	check(sn1, sn2, sn1 == sn2, T);

	local s1 = "Foo";
	local s2 = copy(s1);
	check(s1, s2, s1 == s2, F);

	local pat1 = /.*PATTERN.*/;
	local pat2 = copy(pat1);
	# patterns cannot be directly compared
	if ( same_object(pat1, pat2) )
		print "FAIL P1";
	if ( ! ( pat1 == "PATTERN" ) )
		print "FAIL P2";
	if ( ! ( pat2 == "PATTERN" ) )
		print "FAIL P3";
	if ( pat2 == "PATERN" )
		print "FAIL P4";
	print fmt("orig=%s (%s) clone=%s (%s) same_object=%s", pat1, type_name(pat1), pat2, type_name(pat2), same_object(pat1, pat2));

	local set1 = [1, 2, 3, 4, 5];
	local set2 = copy(set1);
	check(set1, set2, set1 == set2, F);

	local v1 = vector(1, 2, 3, 4, 5);
	local v2 = copy(v1);
	check(v1, v2, check_vector_equal(v1, v2), F);

	local t1 : table[string] of string = table();
	t1["a"] = "va";
	t1["b"] = "vb";
	local t2 = copy(t1);
	check(t1, t2, check_string_table_equal(t1, t2), F);

	local e1 = ENUMME;
	local e2 = copy(ENUMME);
	check(e1, e2, e1 == e2, T);

	local itr = InnerTestRecord($a="a");
	local otr1 = TestRecord($s1="s1", $s2="s2", $i1=itr, $i2=itr);
	local otr2 = copy(otr1);
	check(otr1, otr2, compare_otr(otr1, otr2), F);
	}
