#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is a test";
	local pat = /hi|es/;
	local pat2 = /aa|bb/;

	local b = find_last(a, pat);
	local b2 = find_last(a, pat2);

	print b;
	print "-------------------";
	print |b2|;
	}
