# @TEST-EXEC: zeek -b -r $TRACES/tcp/options.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

event tcp_option(c: connection, is_orig: bool, opt: count, optlen: count)
	{
	print c$id, is_orig, opt, optlen;
	}
