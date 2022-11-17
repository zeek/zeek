# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

const exp_val = -1sec &redef;

global expired: function(tbl: table[int] of string, idx: int): interval;
global data: table[int] of string &write_expire=exp_val &expire_func=expired;

redef table_expire_interval = 1sec;
redef exp_val = 6sec;

global runs = 0;
event do_it()
	{
	++runs;
	print fmt("Run %s", runs);

	if ( runs < 2 )
		schedule 4sec { do_it() };
	else
		terminate();
	}


function expired(tbl: table[int] of string, idx: int): interval
	{
	print fmt("Expired: %s --> %s", idx, tbl[idx]);
	return 0sec;
	}

event zeek_init() &priority=-10
	{
	data[0] = "some data";
	schedule 4sec { do_it() };
	}

# Test that re-defining a table with an expiry in a specific way
# does not crash Zeek; see GH-1687.

global hosts: set[addr] &create_expire=1day &redef;
redef hosts: set[addr] = {};
