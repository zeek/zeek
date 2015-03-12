# Binpac analyzer just for the TLS handshake protocol and nothing else

%include binpac.pac
%include bro.pac

analyzer TLSHandshake withcontext {
	connection: Handshake_Conn;
	flow:       Handshake_Flow;
};

connection Handshake_Conn(bro_analyzer: BroAnalyzer) {
	upflow = Handshake_Flow(true);
	downflow = Handshake_Flow(false);
};

%include ssl-defs.pac
%include tls-handshake-protocol.pac

flow Handshake_Flow(is_orig: bool) {
	flowunit = HandshakePDU(is_orig) withcontext(connection, this);
}

%include tls-handshake-analyzer.pac
