# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function double_string(s: string): string
	{
	return string_cat(s, " ", s);
	}

function triple_string(str: string): string
	{
	return string_cat(str, " ", str, " ", str);
	}

type sample_function: record {
	s: string;
	f: function(str: string): string;
};

event zeek_init()
	{
	local test_sf: sample_function;
	test_sf$s = "Brogrammers, like bowties, are cool.";

	test_sf$f = triple_string;
	print test_sf$f(test_sf$s);

	test_sf$f = double_string;
	print test_sf$f(test_sf$s);

	# Works as expected
	test_sf$f = function(str: string): string
		{ return to_upper(str); };
	print test_sf$f(test_sf$s);

	# Func arg names shouldn't factor into the type check.
	test_sf$f = function(s: string): string
		{ return to_upper(s); };
	print test_sf$f(test_sf$s);
	}
