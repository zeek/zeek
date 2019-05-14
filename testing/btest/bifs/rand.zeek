#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: zeek -b %INPUT do_seed=F >out.2
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff out.2

const do_seed = T &redef;

event zeek_init()
	{
	local a = rand(1000);
	local b = rand(1000);
	local c = rand(1000);

	print a;
	print b;
	print c;

	if ( do_seed )
		srand(575);

	local d = rand(1000);
	local e = rand(1000);
	local f = rand(1000);

	print d;
	print e;
	print f;
	}
