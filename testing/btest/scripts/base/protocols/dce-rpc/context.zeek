# @TEST-EXEC: zeek -b -C -r $TRACES/dce-rpc/cs_window7-join_stream092.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff dce_rpc.log

@load base/protocols/dce-rpc

event dce_rpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count) &priority=5
	{
	print fmt("dce_rpc_bind :: fid  == %s", fid);
	print fmt("dce_rpc_bind :: ctx_id  == %s", ctx_id);
	print fmt("dce_rpc_bind :: uuid == %s", uuid_to_string(uuid));
	}

event dce_rpc_alter_context(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count) &priority=5
	{
	print fmt("dce_rpc_alter_context :: fid  == %s", fid);
	print fmt("dce_rpc_alter_context :: ctx_id  == %s", ctx_id);
	print fmt("dce_rpc_alter_context :: uuid == %s", uuid_to_string(uuid));
	}


event dce_rpc_bind_ack(c: connection, fid: count, sec_addr: string) &priority=5
	{
	print fmt("dce_rpc_bind_ack :: fid      == %s", fid);
	print fmt("dce_rpc_bind_ack :: sec_addr == %s", sec_addr);
	}

event dce_rpc_alter_context_resp(c: connection, fid: count) &priority=5
	{
	print fmt("dce_rpc_alter_context_resp :: fid      == %s", fid);
	}
