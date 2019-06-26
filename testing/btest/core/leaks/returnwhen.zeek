# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: btest-bg-run zeek HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local zeek -m -b %INPUT
# @TEST-EXEC: btest-bg-wait 60

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

event zeek_init()
	{
	local local_dummy = dummyfunc;

	local anon = function(s: string): string { return s + "!"; };

	schedule 1sec { set_flag() };

	when ( local result = async_func("from zeek_init()") )
		{
		print "async_func() return result in zeek_init()", result;
		print local_dummy("from zeek_init() when block");
		print anon("hi");
		if ( result == "timeout" ) terminate();
		schedule 10msec { do_another() };
		}
	}


