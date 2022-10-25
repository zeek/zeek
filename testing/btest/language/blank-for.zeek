# @TEST-DOC: Some blank identifier tests iterating over vectors, tables and strings.
# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output
event zeek_init()
	{
	local vec = vector("a", "b", "c");
	local t1 = table(["keya"] = "a", ["keyb"] = "b", ["keyc"] = "c");
	local t2 = table(["a",1,T] = "a1a", ["b",2,F] = "b2b", ["c",3,T] = "c3c");
	local s = "the string";

	# Ignore just the index.
	print "== vec 1";
	for ( _, v in vec )
		print v;

	# Ignore just the value.
	print "== vec 2";
	local idxsum = 0;
	for ( idx, _ in vec )
		idxsum += idx;
	print "idxsum(vec)", idxsum;

	# Ignore index and value
	print "== vec 3";
	local veclen = 0;
	for ( _, _ in vec )
		++veclen;
	print "veclen(vec)", veclen;

	# Ignore just the key
	print "== t1 1";
	for ( _, v in t1 )
		print v;

	# Ignore just the value
	print "== t1 2";
	for ( k, _ in t1 )
		print k;

	# Ignore index and value
	local t1len = 0;
	print "== t1 3";
	for ( _, _ in t1 )
		++t1len;
	print "t1len", t1len;

	# Ignore part of the index and the value.
	print "== t2 1";
	for ( [_,c,_], v in t2 )
		print c, v;

	# Ignore part of the index and the value.
	print "== t2 2";
	for ( [t2a,_,t2b], _ in t2 )
		print t2a, t2b;

	# Ignore the whole index with a single _
	print "== t2 3";
	local t2concat = "";
	for ( _, v in t2 )
		t2concat += v;
	print "t2concat", t2concat;

	# String iteration ignoring the value
	print "== s";
	local i = 0;
	for ( _ in s )
		++i;
	print "strlen(s)", i;
	}
