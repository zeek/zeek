# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global pt: table[pattern] of count;

redef exit_only_after_terminate = T;

event populate_c()
	{
	print "populate_c()";
	pt[/c/] = 4711;
	terminate();
	}

event populate_b()
	{
	print "populate_b()";
	pt[/b/] = 4242;
	schedule 1msec { populate_c() };
	}

event populate_a()
	{
	print "populate_a()";
	pt[/a/] = 42;
	schedule 1msec { populate_b() };
	}

event hard_exit()
	{
	if ( ! zeek_is_terminating() )
		exit(1);
	}

event zeek_init()
	{
	schedule 5sec { hard_exit() };

	when ( |pt["a"]| > 0 ) {
		print "gotcha a", pt["a"];
	}

	when ( |pt["b"]| > 0 ) {
		print "gotcha b", pt["b"];
	}

	when ( "c" in pt ) {
		print "gotcha c", pt["c"];
	}

	print "schedule populate";
	schedule 1msec { populate_a() };
	}
