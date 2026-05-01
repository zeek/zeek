#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = 1234563.14;
	print a as time;
	local b = -1234563.14;
	print b as time;
	local c = 1.2.3.4;
	print c ?as time;
	}
