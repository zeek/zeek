# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

type MyRecord: record {
	a: string;
	b: string &optional;
};

event zeek_init()
	{
	local vec1 = vector(1, 2, );
	print "vec1", type_name(vec1), vec1;

	local vec2: vector of count = [1, 2, ];
	print "vec2", type_name(vec2), vec2;

	local vec3: vector of count = {1, 2, };
	print "vec3", type_name(vec3), vec3;

	local set1 = set(1, 2, );
	print "set1", type_name(set1), set1;

	local set2 = [1, 2, ];
	print "set2", type_name(set2), set2;

	local set3 = {1, 2, };
	print "set3", type_name(set3), set3;

	local rec1 = MyRecord($a="a", );
	print "rec1", type_name(rec1), rec1;

	local rec2: MyRecord = [$a="a", ];
	print "rec2", type_name(rec2), rec2;

	local rec3 = [];
	print "rec3", type_name(rec3), rec3;

	local tab1: table[string] of count = [
		["a"] = 1,
	];
	print "tab1", type_name(tab1), tab1;

	local tab2: table[string, string] of count = [
		["a", "b"] = 1,
	];
	print "tab2", type_name(tab2), tab2;

	local tab3: table[string, string] of count = {
		["a", "b"] = 1,
	};
	print "tab3", type_name(tab3), tab3;

	# Very verbose
	local tab4: table[string, string] of vector of count = {
		["a", "b"] = vector(
			1,
			2,
		),
		["c", "d"] = vector(
			3,
			4,
		),
	};
	print "tab4", type_name(tab4), tab4;

	# Slightly compressed
	local tab5: table[string, string] of vector of count = {
		["a", "b"] = vector(1, 2,),
		["c", "d"] = vector(3, 4,),
	};
	print "tab5", type_name(tab5), tab5;

	# Inferred types
	local tab6 = table(
		["a", "b"] = vector(1,2,),
		["c", "d"] = vector(3,4,),
	);
	print "tab6", type_name(tab6), tab6;

	local tab7 = table(
		["a", "b"] = set(1, 2, ),
		["c", "d"] = set(3, 4, ),
	);
	print "tab7", type_name(tab7), tab7;

	# Trailing comma in left-hand side in record constructor expression
	# I'm not saying these look good, just that they are possible.
	local tab8: table[MyRecord] of count = {
		[MyRecord(
			$a="a",
			$b="b",
		)] = 42,
		[MyRecord(
			$a="c",
			$b="d",
		)] = 43,
	};
	print "tab8", type_name(tab8), tab8;

	local tab9: table[MyRecord] of count = {
		[[
			$a="abc",
			$b="def",
		]] = 42,
	};
	print "tab9", type_name(tab9), tab9;
	}

@TEST-START-NEXT
# Function calls can have trailing commas.
function f(x: count, y: count) { print fmt("f() x=%s y=%s", x, y); }
f(1, 2,);
