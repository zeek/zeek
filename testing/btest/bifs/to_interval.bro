#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = 1234563.14;
	print double_to_interval(a);
	local b = -1234563.14;
	print double_to_interval(b);
	}
