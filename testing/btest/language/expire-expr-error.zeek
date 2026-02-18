# TODO: This test hangs indefinitely on Windows and is skipped for the time being.
# @TEST-REQUIRES: ! is-windows
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout

redef exit_only_after_terminate = T;

global x: table[string] of interval;
global data: table[int] of string &create_expire=x["kaputt"];

global runs = 0;
event do_it()
	{
	print fmt("Run %s", runs);

	++runs;
	if ( runs < 4 )
		schedule 1sec { do_it() };
	else
		terminate();
	}


event zeek_init() &priority=-10
	{
	data[0] = "some data";
	schedule 1sec { do_it() };
	}
