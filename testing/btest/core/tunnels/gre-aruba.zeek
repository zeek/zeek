# @TEST-EXEC: zeek -b -r $TRACES/tunnels/gre-aruba.pcap %INPUT
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
