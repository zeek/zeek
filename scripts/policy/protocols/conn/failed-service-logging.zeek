##! This script adds the new column ``failed_service`` to the connection log.
##! The column contains the list of protocols in a connection that raised protocol
##! violations causing the analyzer to be removed. Protocols are listed in order
##! that they were removed.

@load base/protocols/conn
@load base/frameworks/analyzer/dpd

module Conn;

redef record Conn::Info += {
	## List of analyzers in a connection that raised violations
	## causing their removal.
	## Analyzers are listed in order that they were removed.
	failed_service: set[string] &log &optional &ordered;
};

event analyzer_failed(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c )
			return;

	local c = info$c;

	# Only add if previously confirmed and not failed
	local analyzer_name = Analyzer::name(atype);
	if ( analyzer_name !in c$service || analyzer_name in c$failed_analyzers )
		return;

	set_conn(c, F);

	local aname = to_lower(Analyzer::name(atype));
	# No duplicate logging
	if ( c$conn?$failed_service && aname in c$conn$failed_service )
		return;

	if ( ! c$conn?$failed_service )
		c$conn$failed_service = set();

	add c$conn$failed_service[aname];
	}
