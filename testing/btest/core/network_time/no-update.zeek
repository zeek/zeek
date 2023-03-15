# @TEST-DOC: Ensure network_time stays 0.0 when configured that way.
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

redef allow_network_time_forward = F;

event zeek_init()
	{
	print network_time(), "zeek_init";
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
