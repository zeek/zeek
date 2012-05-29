#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	print parse_dotted_addr("192.168.0.2");
	print parse_dotted_addr("1234::1");
	}
