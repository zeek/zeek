#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "test ";

	local b = string_fill(1, a);
	local c = string_fill(2, a);
	local d = string_fill(10, a);

	print fmt("*%s* %d", b, |b|);
	print fmt("*%s* %d", c, |c|);
	print fmt("*%s* %d", d, |d|);
	}
