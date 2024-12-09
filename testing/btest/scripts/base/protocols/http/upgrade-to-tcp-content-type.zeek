# @TEST-EXEC: zeek -b -C -r $TRACES/http/docker-http-upgrade.pcap ./common.zeek %INPUT >out
# @TEST-EXEC: btest-diff out

@load ./common.zeek
redef HTTP::upgrade_content_type_analyzers += {
	["tcp", "application/vnd.docker.raw-stream"] = Analyzer::ANALYZER_STREAM_EVENT,
};

# @TEST-START-NEXT
# triggers a HTTP violation because upgrade_analyzers_content_type is
# preferred and it's using HTTP and that's not the right analyzer.
redef HTTP::upgrade_content_type_analyzers += {
	["tcp", "application/vnd.docker.raw-stream"] = Analyzer::ANALYZER_HTTP,
};

redef HTTP::upgrade_analyzers += {
	["tcp"] =  Analyzer::ANALYZER_STREAM_EVENT,
};

# @TEST-START-NEXT
# triggers no violation because upgrade_analyzers_content_type is
# preferred - the reverse of the above test.
redef HTTP::upgrade_content_type_analyzers += {
	["tcp", "application/vnd.docker.raw-stream"] = Analyzer::ANALYZER_STREAM_EVENT,
};

redef HTTP::upgrade_analyzers += {
	["tcp"] =  Analyzer::ANALYZER_HTTP,
};

# @TEST-START-NEXT
# this falls back to upgrade_analyzers and enables the stream event analyzer
# as the content type does not match: cooked in table, raw in trace.
redef HTTP::upgrade_content_type_analyzers += {
	["tcp", "application/vnd.docker.cooked-stream"] = Analyzer::ANALYZER_HTTP,

	# And nope, this does not work!
	["tcp", "application/*"] = Analyzer::ANALYZER_HTTP,
};

redef HTTP::upgrade_analyzers += {
	["tcp"] =  Analyzer::ANALYZER_STREAM_EVENT,
};

# @TEST-START-FILE common.zeek
@load base/protocols/http

event http_connection_upgrade(c: connection, protocol: string)
	{
	print c$uid, fmt("Connection upgraded to %s", protocol);
	}

global deliveries = 0;

event stream_deliver(c: connection, is_orig: bool, data: string)
	{
	++deliveries;
	print c$uid, "stream_deliver", data[:32];

	if ( deliveries == 3 )
		disable_analyzer(c$id, current_analyzer());
	}

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print "analyzer_violation_info", tag, info$reason, info$c$uid, info$aid;
	}
# @TEST-END-FILE
