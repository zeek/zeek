
# @TEST-EXEC: bro -b %INPUT >out1
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: bro -r $TRACES/web.trace %INPUT >out2
# @TEST-EXEC: btest-diff out2

event bro_init()
	{
	print reading_traces();
	}
