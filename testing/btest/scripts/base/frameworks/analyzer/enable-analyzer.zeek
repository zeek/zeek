#
# @TEST-EXEC: zeek -b -r ${TRACES}/var-services-std-ports.trace %INPUT base/protocols/dns base/protocols/conn base/frameworks/dpd
# @TEST-EXEC: cat conn.log | zeek-cut service | grep -q dns
#

redef Analyzer::disable_all = T;

event zeek_init()
	{
	Analyzer::enable_analyzer(Analyzer::ANALYZER_DNS);
	}


