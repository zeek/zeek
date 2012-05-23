#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a: string_array = { 
		[1] = "this", [2] = "is", [3] = "a", [4] = "test" 
	};
	local b: string_vec = vector( "this", "is", "another", "test" );

	print join_string_array(" * ", a);
	print join_string_vec(b, "__");
	}
