#
# @TEST-EXEC: zeek -b %INPUT >out 2>err
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff err

event zeek_init()
	{
	print strptime("%Y-%m-%d", "2012-10-19");
	print strptime("%m", "1980-10-24");
	}
