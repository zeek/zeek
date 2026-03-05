# @TEST-EXEC: zeek -b -r $TRACES/http/get.pcap %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_init()
	{
	print packet_source();
	}
