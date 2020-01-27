# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

# We don't have a foo.bro, but we'll accept foo.zeek.
@load foo.bro

@TEST-START-FILE foo.zeek
event zeek_init()
	{
	print "loaded foo.zeek";
	}
@TEST-END-FILE
