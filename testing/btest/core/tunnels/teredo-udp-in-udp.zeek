# @TEST-EXEC: zeek -r $TRACES/tunnels/teredo-udp-in-udp.pcap %INPUT
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
