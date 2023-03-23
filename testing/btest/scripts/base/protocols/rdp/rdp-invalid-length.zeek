# Tests a pcap that has a known-invalid length in a RDP_Negotiation_Response
# header, ensuring that it throws a binpac exception and reports a notice to
# analyzer.log. The pcap used is a snippet of a pcap from OSS-Fuzz #57109.

# @TEST-EXEC: zeek -C -b -r $TRACES/rdp/rdp-invalid-length.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

@load base/protocols/rdp

event analyzer_violation(c: connection, atype: AllAnalyzers::Tag, aid: count, reason: string) &priority=5
	{
	print "analyzer_violation", reason;
	}