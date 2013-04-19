%include binpac.pac
%include bro.pac

%extern{
#include "SOCKS.h"

#include "events.bif.h"
%}

analyzer SOCKS withcontext {
    connection: SOCKS_Conn;
    flow:       SOCKS_Flow;
};

connection SOCKS_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = SOCKS_Flow(true);
    downflow = SOCKS_Flow(false);
};

%include socks-protocol.pac

flow SOCKS_Flow(is_orig: bool) {
	datagram = SOCKS_Version(is_orig) withcontext(connection, this);
};

%include socks-analyzer.pac
