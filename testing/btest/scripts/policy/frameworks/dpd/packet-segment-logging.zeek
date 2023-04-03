# @TEST-DOC: IPv6 connection from external ipv6.pcap triggering FTP analyzer violation. Check dpd.log contains the right packet_segment
# @TEST-EXEC: zeek -r $TRACES/ftp/ipv6-violation.trace %INPUT
# @TEST-EXEC: btest-diff dpd.log

@load frameworks/dpd/packet-segment-logging

event analyzer_violation(c: connection, atype: AllAnalyzers::Tag, aid: count, reason: string)
	{
	print "analyzer_violation", c$id, atype, aid, reason;
	}

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print "reason", info$reason;
	print "data", fmt("%s", info$data);
	}
