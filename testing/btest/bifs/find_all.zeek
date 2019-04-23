#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is a test";
	local pat = /hi|es/;
	local pat2 = /aa|bb/;

	local b = find_all(a, pat);
	local b2 = find_all(a, pat2);

	for (i in b)
		print i;
	print "-------------------";
	print |b2|;
	}
