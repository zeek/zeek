#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local f1 = "%Y-%m-%d %H:%M:%S";
	local f2 = "%H%M%S %Y%m%d";

	local a = 0 as time;
	print strftime(f1, a);
	print strftime(f2, a);

	a = 123456789 as time;
	print strftime(f1, a);
	print strftime(f2, a);
	}
