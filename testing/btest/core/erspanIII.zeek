# @TEST-EXEC: zeek -C -b -r $TRACES/erspanIII.pcap %INPUT
# @TEST-EXEC: btest-diff tunnel.log
# @TEST-EXEC: btest-diff conn.log

@load base/frameworks/tunnels
@load base/protocols/conn
