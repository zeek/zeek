#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

function myfunc(a: count, b: count): bool
	{
	return a < b;
	}

event bro_init()
	{
	local a = vector( 5, 3, 8 );

	print order(a, myfunc);
	
	print a;

	}
