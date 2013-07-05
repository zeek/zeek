
connection Syslog_Conn(bro_analyzer: BroAnalyzer)
{
	upflow = Syslog_Flow;
	downflow = Syslog_Flow;
};

flow Syslog_Flow
{
	datagram = Syslog_Message withcontext(connection, this);

	function process_syslog_message(m: Syslog_Message): bool
		%{
		BifEvent::generate_syslog_message(connection()->bro_analyzer(),
		                                  connection()->bro_analyzer()->Conn(),
		                                  ${m.PRI.facility},
		                                  ${m.PRI.severity},
		                                  new StringVal(${m.msg}.length(), (const char*) ${m.msg}.begin())
		                                  );
		return true;
		%}

};

refine typeattr Syslog_Message += &let {
	proc_syslog_message = $context.flow.process_syslog_message(this);
};
