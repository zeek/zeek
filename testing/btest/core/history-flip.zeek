# @TEST-EXEC: zeek -C -r $TRACES/tcp/missing-syn.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load policy/protocols/conn/mac-logging
