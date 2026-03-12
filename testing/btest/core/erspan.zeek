# @TEST-EXEC: zeek -b -r $TRACES/erspan.pcap %INPUT
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
