# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type c: count;
function foo(): count
	{
	local bar: any;
	bar = c;
	return when ( 5 > 3 )
		{
		return 9;
		}
	}

event zeek_init()
	{
	when ( local b = foo() )
		print b;
	}
