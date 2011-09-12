%include binpac.pac
%include bro.pac

analyzer Syslog withcontext {
	connection:	Syslog_Conn;
	flow:		Syslog_Flow;
};

connection Syslog_Conn(bro_analyzer: BroAnalyzer)
{
	upflow   = Syslog_Flow;
	downflow = Syslog_Flow;
};

flow Syslog_Flow {
	datagram = Syslog_Message withcontext(connection, this);
}

%include syslog-protocol.pac
%include syslog-analyzer.pac
