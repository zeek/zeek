# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

global my_event: event(a: count, b: string, c: port);
global my_hook: hook(a: count, b: string, c: port);

event my_event(a: count, b: string, c: port)
	{
	print "my_event same order/name", a, b, c;
	}

event my_event(b: string, c: port, a: count)
	{
	print "my_event different order", a, b, c;
	}

event my_event(b: string)
	{
	print "my_event subset", b;
	}

event my_event()
	{
	print "my_event empty";
	}

event my_event(mya: count, myb: string, myc: port)
	{
	print "my_event different names", mya, myb, myc;
	}

event my_event(mya: count, myb: string)
	{
	print "my_event different names subset", mya, myb;
	}

hook my_hook(a: count, b: string, c: port)
	{
	print "my_hook same order/name", a, b, c;
	}

hook my_hook(b: string, c: port, a: count)
	{
	print "my_hook different order", a, b, c;
	}

hook my_hook(b: string)
	{
	print "my_hook subset", b;
	}

hook my_hook()
	{
	print "my_hook empty";
	}

hook my_hook(mya: count, myb: string, myc: port)
	{
	print "my_hook different names", mya, myb, myc;
	}

hook my_hook(mya: count, myb: string)
	{
	print "my_hook different names subset", mya, myb;
	}

event bro_init()
	{
	event my_event(42, "foobar", 80/tcp);
	hook my_hook(42, "foobar", 80/tcp);
	}
