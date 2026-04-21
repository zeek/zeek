# @TEST-DOC: Test some malformed ALPN entries in an SVCB response.
#
# @TEST-EXEC: zeek -r $TRACES/dns/svcb-alpn-malformed-len-too-long.pcap %INPUT >out
# @TEST-EXEC: mv weird.log weird.log-too-long
# @TEST-EXEC: mv out out-too-long
# @TEST-EXEC: btest-diff out-too-long
# @TEST-EXEC: btest-diff-cut -m weird.log-too-long
#
# @TEST-EXEC: zeek -r $TRACES/dns/svcb-alpn-malformed-len-too-short.pcap %INPUT >out
# @TEST-EXEC: mv weird.log weird.log-too-short
# @TEST-EXEC: mv out out-too-short
# @TEST-EXEC: btest-diff out-too-short
# @TEST-EXEC: btest-diff-cut -m weird.log-too-short

@load policy/protocols/dns/auth-addl

event dns_HTTPS(c: connection, msg: dns_msg, ans: dns_answer, https: dns_svcb_rr)
    {
    for (_, param in https$svc_params)
        print param;
    }
