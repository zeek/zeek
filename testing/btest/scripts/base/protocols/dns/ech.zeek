# @TEST-EXEC: zeek -r $TRACES/dns/ech.pcap %INPUT > output
# @TEST-EXEC: btest-diff output

@load policy/protocols/dns/auth-addl

event dns_HTTPS(c: connection, msg: dns_msg, ans: dns_answer, https: dns_svcb_rr)
    {
    for (_, param in https$svc_params)
        print param;
    }
