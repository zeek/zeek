%include binpac.pac
%include zeek.pac

%extern{
#include "Foo.h"

#include "events.bif.h"
%}

analyzer Foo withcontext {
    connection: Foo_Conn;
    flow:       Foo_Flow;
};

connection Foo_Conn(bro_analyzer: ZeekAnalyzer) {
    upflow   = Foo_Flow(true);
    downflow = Foo_Flow(false);
};

%include foo-protocol.pac

flow Foo_Flow(is_orig: bool) {
	datagram = Foo_Message(is_orig) withcontext(connection, this);
};

%include foo-analyzer.pac
