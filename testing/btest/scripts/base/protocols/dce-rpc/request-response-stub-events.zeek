# @TEST-EXEC: zeek -b -C -r $TRACES/dce-rpc/cs_window7-join_stream092.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

@load base/protocols/dce-rpc

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
	{
	print "dce_rpc_request     ", c$id, fid, ctx_id, opnum, stub_len;
	}

event dce_rpc_request_stub(c: connection, fid: count, ctx_id: count, opnum: count, stub: string)
	{
	print "dce_rpc_request_stub", c$id, fid, ctx_id, opnum, |stub|;
	print bytestring_to_hexstr(stub);
	}

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
	{
	print "dce_rpc_response     ", c$id, fid, ctx_id, opnum, stub_len;
	}

event dce_rpc_response_stub(c: connection, fid: count, ctx_id: count, opnum: count, stub: string)
	{
	print "dce_rpc_response_stub", c$id, fid, ctx_id, opnum, |stub|;
	print bytestring_to_hexstr(stub);
	terminate();
	}

