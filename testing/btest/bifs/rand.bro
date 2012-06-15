#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = rand(1000);
	local b = rand(1000);
	local c = rand(1000);

	print a;
	print b;
	print c;

	srand(575);

	local d = rand(1000);
	local e = rand(1000);
	local f = rand(1000);

	print d;
	print e;
	print f;
	}
