# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out


event zeek_init() &priority=10
	{
	print "zeek_init at priority 10!";
	}

event bro_init() &priority=5
	{
	print "bro_init at priority 5!";
	}

event zeek_init() &priority=0
	{
	print "zeek_init at priority 0!";
	}

event bro_init() &priority=-10
	{
	print "bro_init at priority -10!";
	}


event zeek_done() &priority=10
	{
	print "zeek_done at priority 10!";
	}

event bro_done() &priority=5
	{
	print "bro_done at priority 5!";
	}

event zeek_done() &priority=0
	{
	print "zeek_done at priority 0!";
	}

event bro_done() &priority=-10
	{
	print "bro_done at priority -10!";
	}
