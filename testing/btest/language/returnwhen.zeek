# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff bro/.stdout

redef exit_only_after_terminate = T;

global my_set: set[string] = set();
global flag: string = "flag";
global done: bool = F;

function dummyfunc(s: string): string
	{
	return "dummy " + s;
	}

function async_func(s: string): string
	{
	print dummyfunc("from async_func() " + s);

	return when ( flag in my_set )
		{
		return flag + " in my_set";
		}
	timeout 3sec
		{
		return "timeout";
		}
	}

event set_flag()
	{
	add my_set[flag];
	}

event do_another()
	{
	delete my_set[flag];

	local local_dummy = dummyfunc;

	local anon = function(s: string): string { return s + "!"; };

	if ( ! done )
		schedule 1sec { set_flag() };

	when ( local result = async_func("from do_another()") )
		{
		print "async_func() return result in do_another()", result;
		print local_dummy("from do_another() when block");
		print anon("hi");
		if ( result == "timeout" )
			terminate();
		else
			{
			done = T;
			schedule 10msec { do_another() };
			}
		}
	}

event bro_init()
	{
	local local_dummy = dummyfunc;

	local anon = function(s: string): string { return s + "!"; };

	schedule 1sec { set_flag() };

	when ( local result = async_func("from bro_init()") )
		{
		print "async_func() return result in bro_init()", result;
		print local_dummy("from bro_init() when block");
		print anon("hi");
		if ( result == "timeout" ) terminate();
		schedule 10msec { do_another() };
		}
	}


