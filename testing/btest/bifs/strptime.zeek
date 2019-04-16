#
# @TEST-EXEC: bro -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print strptime("%Y-%m-%d", "2012-10-19");
	print strptime("%m", "1980-10-24");
	}
