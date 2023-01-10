# @TEST-DOC: Ensure only the HTTP analyzer is enabled (filter out some noise from the trace)
# @TEST-EXEC: zeek -b -f 'port 53 or port 80'  -r ${TRACES}/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: test ! -f dns.log

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http

# Turn all analyzers off.
redef Analyzer::disable_all = T;

redef Analyzer::requested_analyzers += {
	Analyzer::ANALYZER_HTTP,
};
