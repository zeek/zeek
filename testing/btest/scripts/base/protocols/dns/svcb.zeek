# @TEST-EXEC: zeek -C -r $TRACES/dns-svcb.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_SVCB(c: connection, msg: dns_msg, ans: dns_answer, svcb: dns_svcb_rr)
    {
    print svcb;
    }