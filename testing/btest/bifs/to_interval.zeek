#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = double_to_interval(1234563.140);
	print type_name(a), a;
	local b = double_to_interval(-1234563.14);
	print type_name(b), b;
	local c = double_to_interval(6.0);
	print type_name(c), c;
	}
