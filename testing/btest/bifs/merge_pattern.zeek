#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = /foo/;
	local b = /b[a-z]+/;
	local c = merge_pattern(a, b);

	if ( "bar" == c )
		print "match";

	if ( "foo" == c )
		print "match";

	}
