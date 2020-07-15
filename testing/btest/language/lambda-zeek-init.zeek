# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init() &priority=+10
	{
	local outer = 101;

	local lambda = function()
		{ print outer + 2; };

	lambda();
	}
