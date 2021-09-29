# @TEST-EXEC: zeek -C -r $TRACES/dns-https.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_HTTPS(c: connection, msg: dns_msg, ans: dns_answer, https: dns_svcb_rr)
    {
    print https;
    }