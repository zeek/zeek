# @TEST-DOC: Verify gen-C++ produces a valid CPP-gen.cc file.
#
# -O gen-C++ and -O ZAM (via ZEEK_ZAM=1) are incompatible. Skip for the -a zam runs.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: zeek -b -O gen-C++ %INPUT
# @TEST-EXEC: test -s CPP-gen.cc
# @TEST-EXEC: grep -q "namespace zeek::detail" CPP-gen.cc

event zeek_init()
	{
	print "gen-C++ test";
	}
