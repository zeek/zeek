# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

global my_func: function();

event other_event()
	{
	local baz = 42;
	my_func();
	}

event zeek_init() &priority=+10
	{
	local outer = 101;

	local lambda = function[outer]()
		{ print outer; };

	lambda();

	my_func = lambda;
	my_func();

	event other_event();
	}

event zeek_init() &priority=-10
	{
	local qux = 13;
	my_func();
	}
