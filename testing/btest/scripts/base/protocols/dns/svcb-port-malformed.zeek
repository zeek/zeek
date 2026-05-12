# @TEST-DOC: Test a malformed port entry in an SVCB response.
#
# @TEST-EXEC: zeek -r $TRACES/dns/svcb-port-malformed.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m weird.log
#
@load policy/protocols/dns/auth-addl

event dns_HTTPS(c: connection, msg: dns_msg, ans: dns_answer, https: dns_svcb_rr)
    {
    for (_, param in https$svc_params)
        print param;
    }
