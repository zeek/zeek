# @TEST-EXEC: bro -r $TRACES/socks-auth.pcap %INPUT
# @TEST-EXEC: btest-diff socks.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/protocols/socks
