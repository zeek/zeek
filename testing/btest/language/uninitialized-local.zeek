# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event testit() &priority=10
	{
	local my_count: count = 10;
	}

event testit()
	{
	# my_string's value occupies same Frame offset as my_count's from above
	# handler, but execution of this handler body should still "initialize"
	# it to a null value instead of referring to a left-over value of my_count.
	local my_string: string;
	local my_vector: vector of string;
	my_vector[0] = my_string;
	}

event zeek_init()
	{
	event testit();
	}
