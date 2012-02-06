# This template code contributed to Bro by Kristin Stephens.

%include binpac.pac
%include bro.pac

analyzer Dnp3 withcontext {
	connection:	Dnp3_Conn;
	flow:		Dnp3_Flow;
};

%include dnp3-protocol.pac
%include dnp3-analyzer.pac

