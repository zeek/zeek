#
# @TEST-EXEC: zeek -r ${TRACES}/var-services-std-ports.trace %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut service | grep -vq dns
# @TEST-EXEC: cat conn.log | zeek-cut service | grep -vq ssh
#

redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SSH };

event zeek_init()
	{
	Analyzer::disable_analyzer(Analyzer::ANALYZER_DNS);
	}


