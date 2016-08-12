# @TEST-EXEC: bro -b %INPUT >output
# @TEST-EXEC: btest-diff output

redef exit_only_after_terminate = T;

@load frameworks/communication/listen

const exp_val = -1sec &redef;

global expired: function(tbl: table[int] of string, idx: int): interval;
global data: table[int] of string &write_expire=exp_val &expire_func=expired;

redef table_expire_interval = 1sec;
redef exp_val = 5sec;

global runs = 0;
event do_it()
	{
	print fmt("Run %s", runs);

	++runs;
	if ( runs < 4 )
		schedule 2sec { do_it() };
	else
		terminate();
	}


function expired(tbl: table[int] of string, idx: int): interval
	{
	print fmt("Expired: %s --> %s", idx, tbl[idx]);
	return 0sec;
	}

event bro_init() &priority=-10
	{
	data[0] = "some data";
	schedule 2sec { do_it() };
	}
