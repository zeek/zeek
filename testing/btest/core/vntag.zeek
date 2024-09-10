# @TEST-EXEC: zeek -b -C -r $TRACES/vntag.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn