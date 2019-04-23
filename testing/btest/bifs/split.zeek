#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "this is a test";
	local pat = /hi|es/;
	local idx = vector( 3, 6, 13);

	local b = split(a, pat);
	local c = split1(a, pat);
	local d = split_all(a, pat);
	local e1 = split_n(a, pat, F, 1);
	local e2 = split_n(a, pat, T, 1);

	print b[1];
	print b[2];
	print b[3];
	print "---------------------";
	print c[1];
	print c[2];
	print "---------------------";
	print d[1];
	print d[2];
	print d[3];
	print d[4];
	print d[5];
	print "---------------------";
	print e1[1];
	print e1[2];
	print "---------------------";
	print e2[1];
	print e2[2];
	print e2[3];
	print "---------------------";
	print str_split(a, idx);
	print "---------------------";

	a = "X-Mailer: Testing Test (http://www.example.com)";
	pat = /:[[:blank:]]*/;
	local f = split1(a, pat);

	print f[1];
	print f[2];
	print "---------------------";

	a = "A = B = C = D";
	pat = /=/;
	local g = split_all(a, pat);
	print g[1];
	print g[2];
	print g[3];
	print g[4];
	print g[5];
	print g[6];
	print g[7];
	}
