# @TEST-DOC: Check how many analyzer_confirmation events a vxlan-encapsulated HTTP transaction triggers. Should be 2.
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan-encapsulated-http.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log

@load base/frameworks/tunnels
@load base/protocols/conn
@load base/protocols/http

event analyzer_confirmation_info(tag: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "analyzer_confirmation", info$c$uid, info$c$id, info$aid;
	}

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print "analyzer_violation", info$c$uid, info$c$id, info$aid, info$reason;
	}
