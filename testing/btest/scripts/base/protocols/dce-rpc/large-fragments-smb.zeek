# @TEST-DOC: Synthetic PCAP containing fragments that are 60k in size. Expected to be processed normally. Regression test for #5975.
#
# @TEST-EXEC: zcat <$TRACES/dce-rpc/large-fragments-smb.pcap.gz | zeek -b -Cr - %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m dce_rpc.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/protocols/dce-rpc
@load base/protocols/smb

event dce_rpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
	{
	print fmt("dce_rpc_bind ctx_id=%d uuid=%s ver=%d.%d", ctx_id, uuid_to_string(uuid), ver_major, ver_minor);
	}

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
	{
	print fmt("dce_rpc_request ctx_id=%d opnum=%d stub_len=%d", ctx_id, opnum, stub_len);
	}

event dce_rpc_request_stub(c: connection, fid: count, ctx_id: count, opnum: count, stub: string)
	{
	print fmt("dce_rpc_request_stub len=%d stub=%s...%s", |stub|, stub[0:32], stub[-32:]);
	}

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
	{
	print fmt("dce_rpc_response ctx_id=%d opnum=%d stub_len=%d", ctx_id, opnum, stub_len);
	}

event dce_rpc_response_stub(c: connection, fid: count, ctx_id: count, opnum: count, stub: string)
	{
	print fmt("dce_rpc_response_stub len=%d stub=%s...%s", |stub|, stub[0:32], stub[-32:]);
	}
