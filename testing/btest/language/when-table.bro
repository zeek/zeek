# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff bro/.stdout

redef exit_only_after_terminate = T;

global my_set: set[count] = set();

event set_add()
	{
	add my_set[42];
	}

event bro_init()
	{
	schedule 1sec { set_add() };

	when ( 42 in my_set )
		{
		print "found", my_set;
		}
	timeout 2secs
		{
		print "timeout", my_set;
		}

	when ( 43 in my_set )
		{
		print "found", my_set;
		terminate();
		}
	timeout 2secs
		{
		print "timeout", my_set;
		terminate();
		}
	}


