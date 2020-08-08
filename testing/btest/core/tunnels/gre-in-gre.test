# @TEST-EXEC: zeek -b -r $TRACES/tunnels/gre-within-gre.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
@load base/protocols/conn
