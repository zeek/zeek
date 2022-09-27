# @TEST-DOC: Check how many analyzer_confirmation events a vxlan-encapsulated HTTP transaction triggers. Should be 2.
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/vxlan-encapsulated-http.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log

@load base/frameworks/tunnels
@load base/protocols/conn
@load base/protocols/http

event analyzer_confirmation(c: connection, atype: AllAnalyzers::Tag, aid: count)
	{
	print "analyzer_confirmation", c$uid, c$id, aid;
	}

event analyzer_violation(c: connection, atype: AllAnalyzers::Tag, aid: count, reason: string)
	{
	print "analyzer_violation", c$uid, c$id, aid, reason;
	}
