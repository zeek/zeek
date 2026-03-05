# @TEST-EXEC: zeek -r $TRACES/http/get.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_done()
{
	print(get_event_handler_stats());
}