# @TEST-DOC: Raise a weird when an NXDOMAIN response contains disallowed answer records (RFC 1034 / RFC 2308).
#
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/nxdomain-with-non-cname-answer.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
# @TEST-EXEC: btest-diff-cut -m dns.log

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice/weird
