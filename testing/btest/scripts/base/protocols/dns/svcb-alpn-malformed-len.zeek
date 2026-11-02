# @TEST-DOC: Test some malformed ALPN entries in an SVCB response.
#
# @TEST-EXEC: zeek -r $TRACES/dns/svcb-alpn-malformed-len.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log
#

@load policy/protocols/dns/auth-addl

event dns_HTTPS(c: connection, msg: dns_msg, ans: dns_answer, https: dns_svcb_rr)
    {
    for (_, param in https$svc_params)
        print param;
    }
