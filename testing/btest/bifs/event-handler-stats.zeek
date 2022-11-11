# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_done()
{
	print(get_event_handler_stats());
}