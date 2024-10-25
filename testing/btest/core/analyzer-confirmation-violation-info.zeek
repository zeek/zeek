# @TEST-DOC: The SSL analyzer picks up on the traffic in pppoe-over-qing, but then raises analyzer_violation_info
# @TEST-REQUIRES: ! have-spicy-ssl
# @TEST-EXEC: zeek -r $TRACES/pppoe-over-qinq.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

event analyzer_confirmation_info(tag: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "analyzer_confirmation_info", tag, info$c$id, info$aid;
	}

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print "analyzer_violation_info", tag, info$reason, info$c$id, info$aid;
	}
