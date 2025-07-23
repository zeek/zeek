# @TEST-DOC: Check that connection flip appears in history. Also check that local-orig is flipped correctly.
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/missing-syn.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/http
@load policy/protocols/conn/mac-logging

redef Site::local_nets = { 125.190.109.0/24 };
