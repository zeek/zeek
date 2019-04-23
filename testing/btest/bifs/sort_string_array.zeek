#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a: string_array = { 
		[1] = "this", [2] = "is", [3] = "a", [4] = "test" 
	};

	local b = sort_string_array(a);

	print b[1];
	print b[2];
	print b[3];
	print b[4];
	}
