# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/.stdout

redef exit_only_after_terminate=T;

global myset = set("yes");

event zeek_init()
	{
	when ( "no" in myset )
		{
		print "lookup successful";
		terminate();
		}
	timeout 0.25sec
		{
		print "timeout";
		terminate();
		}
	}
