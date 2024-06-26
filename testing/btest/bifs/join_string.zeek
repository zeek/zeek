#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function set_stringifier(s: set[count]): string
	{
	local tmp: set[string];
	for ( x in s )
		add tmp[cat(x)];

	return join_string_set(tmp, ";");
	}

event zeek_init()
	{
	local a: string_array = {
		[1] = "this", [2] = "is", [3] = "a", [4] = "test"
	};
	local b: string_array = { [1] = "mytest" };
	local c: string_vec = vector( "this", "is", "another", "test" );
	local d: string_vec = vector( "Test" );
	local e: string_vec = vector();
	e[3] = "hi";
	e[5] = "there";

	print join_string_vec(c, "__");
	print join_string_vec(c, "");
	print join_string_vec(d, "-");
	print join_string_vec(e, ".");
	print join_string_vec(c, "\x00");

	local empty_set: set[string] = set();
	print fmt("%s (empty)", join_string_set(empty_set, ", "));
	print join_string_set(set("one"), ", ");
	print join_string_set(set("one", "two", "three"), ", ");
	print join_string_set(set("one", "two"), "");

	print join_any_vec(vector(1, 2, 3), ",");
	print join_any_vec(vector(1, 2, 3), ",", cat);
	print join_any_vec(vector(1, 2, 3), ",", function(x: count): string { return cat(x + 1); });
	print join_any_vec(vector("a", "b", "c", "d"), ",");
	print join_any_vec(vector(set(1, 10), set(2, 20), set(3, 30), set(4, 40)), ",", set_stringifier);
	local v = vector(1.0.0.0, 2.0.0.0, 3.0.0.0, 4.0.0.0);
	v[5] = 5.0.0.0;
	print join_any_vec(v, ",");
	print join_any_vec(v, ",", function(x: addr): string { return cat(x/24); });
	}
