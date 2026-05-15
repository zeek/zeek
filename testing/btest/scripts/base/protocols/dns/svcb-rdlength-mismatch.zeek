# @TEST-DOC: Test malformed SVCB RDATA where RDLENGTH is shorter than minimum.
#
# @TEST-EXEC: zeek -b -C -r $TRACES/dns-svcb-rdlength-mismatch.pcap %INPUT >out
# @TEST-EXEC: test ! -s out
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird
@load policy/protocols/dns/auth-addl

event dns_SVCB(c: connection, msg: dns_msg, ans: dns_answer, svcb: dns_svcb_rr)
    {
    print svcb;
    }
