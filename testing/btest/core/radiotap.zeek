# @TEST-EXEC: zeek -b -C -r $TRACES/radiotap.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
@load base/protocols/dns
