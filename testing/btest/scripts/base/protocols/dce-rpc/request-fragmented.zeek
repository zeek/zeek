# @TEST-DOC: A DCE-RPC request stub fragmented over three valid REQUEST PDUs (bind ctx 7 -> epmapper, call_id 2, opnum 3, 50-byte slices A/B/C). tshark reassembles a 150-byte stub; Zeek previously only produced the last 50 byte stub data filled with C, instead of the 150 bytes with A, B and C chunks.
#
# @TEST-EXEC: zeek -b -r $TRACES/dce-rpc/request-fragmented-3x.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/conn
@load base/protocols/dce-rpc

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
        print fmt("dce_rpc_request_stub len=%d stub=%s", |stub|, stub);
        }
