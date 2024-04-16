
#include "Foo.h"

#include "zeek/EventRegistry.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

#include "events.bif.h"
#include "foo_pac.h"

using namespace btest::plugin::Demo_Foo;
using namespace std::placeholders;

Foo::Foo(zeek::Connection* conn) : zeek::analyzer::tcp::TCP_ApplicationAnalyzer("Foo", conn) {
    interp = new binpac::Foo::Foo_Conn(this);

    auto handler = zeek::event_registry->Lookup("connection_established");
    if ( handler ) {
        handler->GetFunc()->AddBody([](const zeek::Args& args, zeek::detail::StmtFlowType& flow) {
            printf("c++ connection_established lambda handler, received %zu arguments\n", args.size());
        });

        handler->GetFunc()->AddBody(std::bind(&Foo::ConnectionEstablishedHandler, this, _1, _2));
    }
}

Foo::~Foo() { delete interp; }

void Foo::ConnectionEstablishedHandler(const zeek::Args& args, zeek::detail::StmtFlowType& flow) {
    printf("c++ connection_established member handler, received %zu arguments\n", args.size());
}

void Foo::Done() {
    zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

    interp->FlowEOF(true);
    interp->FlowEOF(false);
}

void Foo::EndpointEOF(bool is_orig) {
    zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
}

void Foo::DeliverStream(int len, const u_char* data, bool orig) {
    zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    if ( TCP() && TCP()->IsPartial() )
        return;

    try {
        interp->NewData(orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
    }
}

void Foo::Undelivered(uint64_t seq, int len, bool orig) {
    zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    interp->NewGap(orig, len);
}
