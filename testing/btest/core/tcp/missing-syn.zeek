# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/missing-syn.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
@load base/protocols/http
