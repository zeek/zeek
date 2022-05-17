# @TEST-EXEC: zeek %INPUT >>output
# @TEST-EXEC: zeek -b %INPUT >>output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	print bare_mode();
	}
