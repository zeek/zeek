#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "This is a test";
	local b: string;
	local c = "This is a test";
	b = a;
	print same_object(a, b);
	print same_object(a, c);

	local d = vector(1, 2, 3);
	print same_object(a, d);
	}
