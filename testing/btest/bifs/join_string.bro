#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a: string_array = { 
		[1] = "this", [2] = "is", [3] = "a", [4] = "test" 
	};
	local b: string_array = { [1] = "mytest" };
	local c: string_vec = vector( "this", "is", "another", "test" );
	local d: string_vec = vector( "Test" );

	print join_string_array(" * ", a);
	print join_string_array("", a);
	print join_string_array("x", b);

	print join_string_vec(c, "__");
	print join_string_vec(c, "");
	print join_string_vec(d, "-");
	}
