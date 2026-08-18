# @TEST-EXEC: zeek -b -r $TRACES/http/get.pcap %INPUT >out
# @TEST-EXEC: btest-diff-remove-abspath out

event zeek_init()
	{
	print packet_source();
	}
