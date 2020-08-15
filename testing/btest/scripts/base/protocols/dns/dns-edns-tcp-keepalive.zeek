# @TEST-EXEC: zeek -C -r $TRACES/dns-edns-tcp-keepalive.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
@load policy/protocols/dns/auth-addl

event dns_EDNS_tcp_keepalive(c: connection, msg: dns_msg, opt: dns_edns_tcp_keepalive)
    {
        print opt;
    }