# @TEST-DOC: Ensure dce_rpc_backing state stays bounded when pipes are closed properly.
# @TEST-EXEC: zeek -C -r $TRACES/dce-rpc/20-fids.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/smb
@load base/protocols/dce-rpc

redef SMB::max_dce_rpc_analyzers = 5;

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
	{
	print "dce_rpc_request", c$uid, "fid", fid, "backing", |c$dce_rpc_backing|;
	}

event smb_discarded_dce_rpc_analyzers(c: connection)
	{
	print "UNEXPECTED", "smb_discarded_dce_rpc_analyzers", c$uid;
	}
