# @TEST-EXEC: zeek -C -r $TRACES/ncp.pcap %INPUT NCP::max_frame_size=150 >out
# @TEST-EXEC: btest-diff out

redef likely_server_ports += { 524/tcp };

event zeek_init()
	{
	const ports = { 524/tcp };
	Analyzer::register_for_ports(Analyzer::ANALYZER_NCP, ports);
	}

event ncp_request(c: connection, frame_type: count, length: count, func: count)
	{
	print "ncp request", frame_type, length, func;
	}

event ncp_reply(c: connection, frame_type: count, length: count, req_frame: count, req_func: count, completion_code: count)
	{
	print "ncp reply", frame_type, length, req_frame, req_func, completion_code;
	}
