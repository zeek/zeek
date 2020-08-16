# @TEST-EXEC: zeek -C -r $TRACES/dns-edns-cookie.pcap %INPUT > output
# @TEST-EXEC: btest-diff output
@load policy/protocols/dns/auth-addl

event dns_EDNS_cookie(c: connection, msg: dns_msg, opt: dns_edns_cookie)
    {
        print opt;
    } 