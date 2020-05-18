# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: btest-diff out

event my_init()
	{
	# Expect time to be initialized (PktSrc was processed at least once).
	print network_time();
	}

event zeek_init()
	{
	# Expect time to be zero
	print network_time();
	schedule 0sec { my_init() };
	}
