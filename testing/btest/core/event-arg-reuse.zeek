# @TEST-DOC: Check that assignment to event parameters isn't visible to other handlers.
#
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

event f(a: int) &priority=5
	{
	a = 2;
	print "f1", a;
	}

event f(a: int) &priority=-5
	{
	print "f2", a;
	}

event zeek_init()
	{
	event f(1);
	}
