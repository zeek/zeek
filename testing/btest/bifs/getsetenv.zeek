#
# @TEST-EXEC: TESTBRO=testvalue zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = getenv("NOTDEFINED");
	local b = getenv("TESTBRO");
	if ( |a| == 0 )
		print "OK";
	if ( b == "testvalue" )
		print "OK";

	if ( setenv("NOTDEFINED", "now defined" ) == T )
		{
		if ( getenv("NOTDEFINED") == "now defined" )
			print "OK";
		}

	}
