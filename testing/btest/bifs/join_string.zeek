#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

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

	print join_string_array(" * ", a);
	print join_string_array("", a);
	print join_string_array("x", b);

	print join_string_vec(c, "__");
	print join_string_vec(c, "");
	print join_string_vec(d, "-");
	print join_string_vec(e, ".");
	}
