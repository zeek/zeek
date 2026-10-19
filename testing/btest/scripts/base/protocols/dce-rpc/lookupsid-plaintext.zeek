# @TEST-DOC: PCAP containing a large fragmented LsarLookupSids request.
#
# @TEST-EXEC: zcat <$TRACES/dce-rpc/lookupsid-plaintext.pcap.gz | zeek -b -Cr - %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m dce_rpc.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: test ! -f analyzer.log

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
