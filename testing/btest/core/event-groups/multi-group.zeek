# @TEST-DOC: Test support for multiple &group attributes
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	print "zeek_init";

	disable_event_group("my-group2");
	}

event zeek_done() &group="my-group1" &group="my-group2"
	{
	print "FAIL: zeek_done with group my-group1, my-group2";
	}

event zeek_done() &group="my-group2" &group="my-group1"
	{
	print "FAIL: zeek_done with group my-group2, my-group1";
	}

event zeek_done() &group="my-group2"
	{
	print "FAIL: zeek_done with group my-group2";
	}

event zeek_done() &group="my-group1"
	{
	print "zeek_done with group my-group1";
	}

event zeek_done()
	{
	print "zeek_done without groups";
	}
