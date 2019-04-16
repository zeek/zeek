#
# @TEST-EXEC: bro -r ${TRACES}/var-services-std-ports.trace %INPUT
# @TEST-EXEC: cat conn.log | bro-cut service | grep -vq dns
# @TEST-EXEC: cat conn.log | bro-cut service | grep -vq ssh
#

redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SSH };

event bro_init()
	{
	Analyzer::disable_analyzer(Analyzer::ANALYZER_DNS);
	}


