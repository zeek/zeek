#
# @TEST-EXEC: bro -r ${TRACES}/var-services-std-ports.trace %INPUT
# @TEST-EXEC: cat conn.log | bro-cut service | grep -q dns
#

redef Analyzer::disable_all = T;

event bro_init()
	{
	Analyzer::enable_analyzer(Analyzer::ANALYZER_DNS);
	}


