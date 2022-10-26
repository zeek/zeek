# @TEST-DOC: Enabling/disabling groups at runtime driven by ticks.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

event e1(c: count) {
	print c, "e1-no-group";
}
event e2(c: count) {
	print c, "e2-no-group";
}

event e1(c: count) &group="group1" {
	print c, "e1-group1";
}
event e2(c: count) &group="group1" {
	print c, "e2-group1";
}

event e3(c: count) &group="group2" {
	print c, "e3-group2";
}

event tick(c: count)
	{
	event e1(c);
	event e2(c);
	event e3(c);

	if ( c == 4 )
		{
		print "disable group1";
		disable_event_group("group1");
		}

	if ( c == 1 )
		{
		print "enable group1";
		enable_event_group("group1");
		}

	--c;
	if ( c > 0 )
		event tick(c);

	}

event zeek_init()
	{
	event tick(5);
	}
