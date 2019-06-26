# @TEST-EXEC: zeek -C -r $TRACES/ipv4/fragmented-1.pcap %INPUT >>output
# @TEST-EXEC: zeek -C -r $TRACES/ipv4/fragmented-2.pcap %INPUT >>output
# @TEST-EXEC: zeek -C -r $TRACES/ipv4/fragmented-3.pcap %INPUT >>output
# @TEST-EXEC: zeek -C -r $TRACES/ipv4/fragmented-4.pcap %INPUT >>output
# @TEST-EXEC: zeek -C -r $TRACES/tcp/reassembly.pcap %INPUT >>output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	print "----------------------";
	}

event flow_weird(name: string, src: addr, dst: addr)
	{
	print "flow weird", name, src, dst;
	}

event net_weird(name: string)
	{
	print "net_weird", name;
	}

event rexmit_inconsistency(c: connection, t1: string, t2: string, tcp_flags: string)
	{
	print "rexmit_inconsistency", c$id, t1, t2, tcp_flags;
	}
