# @TEST-EXEC: zeek -b -r $TRACES/rpc-portmap-sadmind.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

const rpc_ports = { 111/udp };
redef likely_server_ports += { rpc_ports };

event zeek_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_PORTMAPPER, rpc_ports);
	}

event pm_request_getport(r: connection, pr: pm_port_request, p: port)
	{
	print "portmap request getport", r$id$orig_p, pr, p;
	}

event pm_request_callit(r: connection, call: pm_callit_request, p: port)
	{
	print "portmap request callit", r$id$orig_p, call, p;
	}

event rpc_call(c: connection, xid: count, prog: count, ver: count, proc: count, call_len: count)
	{
	print "rpc call", c$id$orig_p, xid, prog, ver, proc, call_len;
	}

event rpc_reply(c: connection, xid: count, status: rpc_status, reply_len: count)
	{
	print "rpc reply", c$id$orig_p, xid, status, reply_len;
	}
