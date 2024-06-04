# Verifies analyzer ID retrieval from a connection.
#
# @TEST-EXEC: zeek -b -r ${TRACES}/ssh/ssh-on-port-80.trace %INPUT >output
# @TEST-EXEC: btest-diff output

# This first test should trigger two analyzer violations since the given pcap
# has non-HTTP content on port 80, which triggers one violation each for the
# missing request and response lines.

@load base/protocols/http

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print atype;
	}

# @TEST-START-NEXT

# This one should not trigger violations since we suppress HTTP analysis when
# the TCP connection establishes.

@load base/protocols/http

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print atype;
	}

event connection_established(c: connection)
	{
	local aid = lookup_connection_analyzer_id(c$id, Analyzer::ANALYZER_HTTP);
	if ( aid > 0 )
		disable_analyzer(c$id, aid, T, T);
	}

# @TEST-START-NEXT

# This one validates the return values of analyzer ID lookup calls for valid &
# invalid connection IDs and analyzers.

@load base/protocols/http

event connection_established(c: connection)
	{
	assert lookup_connection_analyzer_id(c$id, Analyzer::ANALYZER_HTTP) != 0;

	local wrong_cid = copy(c$id);
	wrong_cid$orig_h = 1.2.3.4;

	assert lookup_connection_analyzer_id(wrong_cid, Analyzer::ANALYZER_HTTP) == 0;
	}
