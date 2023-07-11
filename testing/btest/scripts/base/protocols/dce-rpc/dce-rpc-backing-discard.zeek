# @TEST-DOC: Pcap does not contain close requests for the involved fids (filtered out with wireshark)
# @TEST-EXEC: zeek -C -r $TRACES/dce-rpc/20-fids-no-close.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/smb
@load base/protocols/dce-rpc

redef SMB::max_dce_rpc_analyzers = 5;

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
	{
	print "dce_rpc_request", c$uid, "fid", fid, "backing", |c$dce_rpc_backing|;
	}

event smb_discarded_dce_rpc_analyzers(c: connection)
	{
	print "smb_discarded_dce_rpc_analyzers", c$uid;
	}
