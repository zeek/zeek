# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event Pcap::file_done(path: string)
	{
	print "pcap file done", path;
	}
