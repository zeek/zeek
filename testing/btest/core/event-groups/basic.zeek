# @TEST-DOC: Very basic testing of event groups with zeek_init / zeek_done.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	print "zeek_init";

	# Disable the my-group1 group
	disable_event_group("my-group1");
	}

# Disabled above and shouldn't show.
event zeek_done() &group="my-group1"
	{
	print "FAIL: zeek_done with group my-group1";
	}

event zeek_done()
	{
	print "zeek_done without group";
	}

event zeek_done() &group="my-group2"
	{
	print "zeek_done with group my-group2";
	}
