# @TEST-DOC: Ensure that event coalescence doesn't happen if inlining turned off.
#
# @TEST-EXEC: zeek -b -O ZAM -O no-inline %INPUT >output
# @TEST-EXEC: btest-diff output

event my_event() &priority=-10
	{
	print "first instance, lower priority";
	}

event my_event() &priority=10
	{
	print "second instance, higher priority";
	}

event zeek_init()
	{
	# This should print two event handler bodies.
	print my_event;

	# Make sure execution of both handlers happens properly.
	event my_event();
	}
