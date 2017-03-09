
%include binpac.pac
%include bro.pac

analyzer AYIYA withcontext {
	connection:	AYIYA_Conn;
	flow:		AYIYA_Flow;
};

%include ayiya-protocol.pac
%include ayiya-analyzer.pac
