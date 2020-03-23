# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

event zeek_init() &priority=-10
	{
	print "zeek_init at priority -10!";
	}

event zeek_init() &priority=10
	{
	print "zeek_init at priority 10!";
	}

event zeek_init() &priority=0
	{
	print "zeek_init at priority 0!";
	}

event zeek_done() &priority=-10
	{
	print "zeek_done at priority -10!";
	}

event zeek_done() &priority=0
	{
	print "zeek_done at priority 0!";
	}

event zeek_done() &priority=10
	{
	print "zeek_done at priority 10!";
	}
