# @TEST-EXEC: zeek -b -r $TRACES/tcp/truncated-header.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
	{
	# Just having this handler used to crash Bro on this trace.
        print network_time(), c$id;
	}

