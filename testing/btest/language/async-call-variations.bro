# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

function foo2()
	{
	print "foo2 begin";
	local h = async lookup_addr(192.150.187.43);
	print "foo2 end", h;
	}

function foo1()
	{
	foo2();
	}

function foo3(i: int)
	{
	print "foo3", i, "begin";

	if ( i == 0 )
		return;
	
	local h = async lookup_addr(192.150.187.43);
	print "foo3", i, "end", h;
	foo3(i - 1);
	}

function foo_no_async()
	{
	print "foo_no_async";
	}

event bro_init()
	{
	foo1();
	}

event bro_init()
	{
	foo3(10);
	}

event bro_init()
	{
	# No async here.
	foo_no_async();
	}

