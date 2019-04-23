#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a: string_array = { 
		[0] = "this", [1] = "is", [2] = "a", [3] = "test" 
	};

	print cat_string_array(a);
	print cat_string_array_n(a, 0, |a|-1);
	print cat_string_array_n(a, 1, 2);
	}
