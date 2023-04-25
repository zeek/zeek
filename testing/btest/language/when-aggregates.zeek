# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff zeek/.stdout

type r: record { x: int; y: int; };

global g = 0;

function async_foo1(arg: r) : r
	{
	return when [copy arg] ( g > 0 )
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

	when [copy orig1] ( g == 1 && local resp1 = async_foo1(orig1) )
		{
		++g;
		print orig1, resp1;
		}

	when [orig2] ( g == 2 && local resp2 = async_foo1(orig2) )
		{
		++g;
		print orig2, resp2;
		}

	# The when within async_foo2 does not copy, so orig3 and orig4
	# within the when body are modified with.
	local orig3 = r($x = 111, $y = 222);
	local orig4 = copy(orig3);

	when [copy orig3] ( g == 3 && local resp4 = async_foo2(orig3) )
		{
		++g;
		print orig3, resp4;
		}

	when [orig4] ( g == 4 && local resp5 = async_foo2(orig4) )
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
