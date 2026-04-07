# @TEST-DOC: As of now, loading a package directory with a .so suffix works as we'll try open the package.so/__load__.zeek file before trying suffix matching on the @load.
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

# @TEST-START-FILE package.so/__load__.zeek
event zeek_init()
	{
	print "package.so/__load__.zeek";
	}
# @TEST-END-FILE

@load ./package.so
