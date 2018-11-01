#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "this is a test";
	local pat = /hi|es/;
	local pat2 = /aa|bb/;

	local b = rfind(a, pat);
	local b2 = rfind(a, pat2);

	print b;
	print "-------------------";
	print b2;
	}
