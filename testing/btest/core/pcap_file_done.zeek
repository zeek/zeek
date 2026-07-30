# @TEST-EXEC: zeek -b -r $TRACES/http/get.pcap %INPUT >out
# @TEST-EXEC: btest-diff-remove-abspath out

event Pcap::file_done(path: string)
	{
	print "pcap file done", path;
	}
