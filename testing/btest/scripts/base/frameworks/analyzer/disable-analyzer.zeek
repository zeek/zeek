#
# @TEST-EXEC: zeek -b -r ${TRACES}/var-services-std-ports.trace %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut service > service.out
# @TEST-EXEC-FAIL: grep -q ssh service.out
# @TEST-EXEC-FAIL: grep -q dns service.out

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssh

redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SSH };

event zeek_init()
	{
	Analyzer::disable_analyzer(Analyzer::ANALYZER_DNS);
	}


