# @TEST-DOC: Ensure setting network time is reflected in following events.
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

redef allow_network_time_forward = F;

event zeek_init()
	{
	print network_time(), "zeek_init (1)";
	set_network_time(double_to_time(1.5));
	}

event zeek_init() &priority=-1
	{
	print network_time(), "zeek_init (2)";
	set_network_time(double_to_time(2.5));
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
