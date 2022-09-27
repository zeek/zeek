# @TEST-DOC: The SSL analyzer picks up on the traffic in pppoe-over-qing, but then raises analyzer_violation_info
# @TEST-EXEC: zeek -r $TRACES/pppoe-over-qinq.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

event analyzer_confirmation_info(tag: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "analyzer_confirmation_info", tag, info$c$id, info$aid;
	}

event analyzer_confirmation(c: connection, tag: AllAnalyzers::Tag, aid: count)
	{
	print "analyzer_confirmation", tag, c$id, aid;
	}

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print "analyzer_violation_info", tag, info$reason, info$c$id, info$aid;
	}

event analyzer_violation(c: connection, tag: AllAnalyzers::Tag, aid: count, reason: string)
	{
	print "analyzer_violation", tag, reason, c$id, aid;
	}
