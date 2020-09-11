# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/single-rst.pcap %INPUT >out
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/syn-then-rst.pcap %INPUT >>out
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/syn-then-ack-then-rst.pcap %INPUT >>out
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/syn-then-stuff-then-rst.pcap %INPUT >>out
# @TEST-EXEC: btest-diff out

@load base/protocols/conn

event connection_state_remove(c: connection)
	{
	print c$history, c$conn$conn_state;
	}
