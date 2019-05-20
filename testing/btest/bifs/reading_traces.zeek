
# @TEST-EXEC: zeek -b %INPUT >out1
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: zeek -r $TRACES/web.trace %INPUT >out2
# @TEST-EXEC: btest-diff out2

event zeek_init()
	{
	print reading_traces();
	}
