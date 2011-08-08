# This template is for DNP3-Over-TCP

%include binpac.pac
%include bro.pac

analyzer Dnp3TCP withcontext {
	connection:	Dnp3TCP_Conn;
	flow:		Dnp3TCP_Flow;
};

%include dnp3-tcp-protocol.pac
%include dnp3-tcp-analyzer.pac

