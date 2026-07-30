# @TEST-EXEC: zeek -b %INPUT >out 2>err
# @TEST-EXEC: btest-diff-remove-abspath out
# @TEST-EXEC: btest-diff-remove-abspath err

event zeek_init()
	{
	local i = 32;
	print 1.2.3.4/i;
	++i;
	print 1.2.3.4/i;
	print "init 1";
	}

event zeek_init()
	{
	local i = 128;
	print [::]/i;
	++i;
	print [::]/i;
	print "init 1";
	}

event zeek_init() &priority=-10
	{
	print "init last";
	}

