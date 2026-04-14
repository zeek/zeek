# @TEST-DOC: Verify gen-C++ produces a valid CPP-gen.cc file.
#
# @TEST-EXEC: zeek -b -O gen-C++ %INPUT
# @TEST-EXEC: test -s CPP-gen.cc
# @TEST-EXEC: grep -q "namespace zeek::detail" CPP-gen.cc

event zeek_init()
	{
	print "gen-C++ test";
	}
