# @TEST-EXEC: zeek -b -r $TRACES/pbb.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
