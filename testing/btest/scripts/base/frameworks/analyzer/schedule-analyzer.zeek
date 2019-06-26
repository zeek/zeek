#
# @TEST-EXEC: zeek -b  -r ${TRACES}/rotation.trace %INPUT | sort >output
# @TEST-EXEC: btest-diff output

global x = 0;

event new_connection(c: connection)
	{
	# Make sure expiration executes.
	Analyzer::schedule_analyzer(1.2.3.4, 1.2.3.4, 8/tcp, Analyzer::ANALYZER_MODBUS, 100hrs);
	
	if ( x > 0 )
		return;

	x = 1;

	Analyzer::schedule_analyzer(10.0.0.2, 10.0.0.3, 6/tcp, Analyzer::ANALYZER_SSH, 100hrs);
	Analyzer::schedule_analyzer(10.0.0.2, 10.0.0.3, 6/tcp, Analyzer::ANALYZER_HTTP, 100hrs);
	Analyzer::schedule_analyzer(10.0.0.2, 10.0.0.3, 6/tcp, Analyzer::ANALYZER_DNS, 100hrs);
	Analyzer::schedule_analyzer(0.0.0.0, 10.0.0.3, 6/tcp, Analyzer::ANALYZER_FTP, 100hrs);
	
	Analyzer::schedule_analyzer(10.0.0.2, 10.0.0.3, 7/tcp, Analyzer::ANALYZER_SSH, 1sec);
	Analyzer::schedule_analyzer(10.0.0.2, 10.0.0.3, 8/tcp, Analyzer::ANALYZER_HTTP, 1sec);
	Analyzer::schedule_analyzer(10.0.0.2, 10.0.0.3, 8/tcp, Analyzer::ANALYZER_DNS, 100hrs);
	Analyzer::schedule_analyzer(10.0.0.2, 10.0.0.3, 9/tcp, Analyzer::ANALYZER_FTP, 1sec);
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag)
	{
	print "APPLIED:", network_time(), c$id, a;
	}





