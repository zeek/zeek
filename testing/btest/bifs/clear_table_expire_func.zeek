# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-DOC: Checks use of clear_table() within an &expire_func works.

redef exit_only_after_terminate=T;
redef table_expire_interval = 1msec;

global myexpire: function(t: table[count] of count, i: count): interval;

global mt: table[count] of count &create_expire=1msec &expire_func=myexpire;

function myexpire(t: table[count] of count, i: count): interval
	{
	print "expire";
	clear_table(mt);
	terminate();
	return 0secs;
	}

event zeek_init()
	{
	mt[0] = 0;
	mt[1] = 1;
	mt[2] = 2;
	}

