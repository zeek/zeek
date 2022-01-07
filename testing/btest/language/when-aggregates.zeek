# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff zeek/.stdout

type r: record { x: int; y: int; };

global g = 0;

function async_foo1(arg: r) : r
	{
	return when ( g > 0 )
		{
		arg$x = 99;
		return r($x = 11, $y = 12);
		}
	}

function async_foo2(arg: r) : r
	{
	return when [arg] ( g > 0 )
		{
		arg$x = 99;
		return r($x = 13, $y = 14);
		}
	}

event zeek_init()
	{
	local orig1 = r($x = 1, $y = 2);
	local orig2 = copy(orig1);

	when ( local resp1 = async_foo1(orig1) )
		{
		print orig1, resp1;
		}

	when [orig2] ( local resp2 = async_foo1(orig2) )
		{
		print orig2, resp2;
		}

	local orig3 = r($x = 111, $y = 222);
	local orig4 = copy(orig3);

	when ( local resp4 = async_foo2(orig3) )
		{
		print orig3, resp4;
		}

	when [orig4] ( local resp5 = async_foo2(orig4) )
		{
		print orig4, resp5;
		}

	orig1$y = 44;
	orig2$y = 55;
	}

event zeek_init() &priority=-10
	{
	g = 1;
	}
