# @TEST-EXEC: btest-bg-run broproc bro %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: cat broproc/.stderr > output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

global x: table[string] of interval;
global data: table[int] of string &create_expire=x["kaputt"];

@load frameworks/communication/listen

global runs = 0;
event do_it()
	{
	print fmt("Run %s", runs);

	++runs;
	if ( runs < 4 )
		schedule 1sec { do_it() };
	}


event bro_init() &priority=-10
	{
	data[0] = "some data";
	schedule 1sec { do_it() };
	}



