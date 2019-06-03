# @TEST-EXEC: zeek -r $TRACES/socks-auth.pcap %INPUT
# @TEST-EXEC: btest-diff socks.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/protocols/socks

redef SOCKS::default_capture_password = T;

@TEST-START-NEXT

@load base/protocols/socks
