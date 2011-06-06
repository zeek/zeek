%include binpac.pac
%include bro.pac

analyzer Syslog withcontext {
	connection:	Syslog_Conn;
	flow:		Syslog_Flow;
};

%include syslog-protocol.pac
%include syslog-analyzer.pac
