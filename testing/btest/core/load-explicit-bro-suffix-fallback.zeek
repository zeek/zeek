# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# We don't have a foo.bro, but we'll accept foo.zeek.
@load foo.bro

@TEST-START-FILE foo.zeek
event zeek_init()
	{
	print "loaded foo.zeek";
	}
@TEST-END-FILE
