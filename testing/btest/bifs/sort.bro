#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

function myfunc(aa: interval, bb: interval): bool
	{
	return aa < bb;
	}

event bro_init()
	{
	local a = vector( 5, 2, 8, 3 );
	print sort(a);

	local b = vector( 5hr, 1sec, 7min );
	print sort(b, myfunc);
	}
