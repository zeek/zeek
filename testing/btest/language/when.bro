# @TEST-SERIALIZE: comm
# @TEST-EXEC: btest-bg-run test1 bro %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: mv test1/.stdout out
# @TEST-EXEC: btest-diff out

@load frameworks/communication/listen

event bro_init()
{
	local h1: addr = 127.0.0.1;

	when ( local h1name = lookup_addr(h1) )
		{ 
		print "lookup successful";
		terminate();
		}
	print "done";
}

