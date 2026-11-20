# @TEST-DOC: Reject two oversized Kerberos ETYPE arrays, one with many valid INTEGERs and one with a single oversized non-INTEGER.
#
# @TEST-EXEC: zeek -b -r $TRACES/krb/etype-array-limit.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m analyzer_debug.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/krb
@load base/frameworks/notice/weird
@load frameworks/analyzer/debug-logging

global requests: count = 0;

event krb_as_request(c: connection, msg: KRB::KDC_Request)
	{
	++requests;
	}

event zeek_done()
	{
	print "krb_as_requests", requests;
	}
