
%include binpac.pac
%include bro.pac

analyzer DNP3 withcontext {
	connection:	DNP3_Conn;
	flow:		DNP3_Flow;
};

%include dnp3-protocol.pac
%include dnp3-analyzer.pac

