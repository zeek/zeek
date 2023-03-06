
#include "Foo.h"

#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

#include "events.bif.h"
#include "foo_pac.h"

using namespace btest::plugin::Demo_Foo;

Foo::Foo(zeek::Connection* conn) : zeek::analyzer::tcp::TCP_ApplicationAnalyzer("Foo", conn)
	{
	interp = new binpac::Foo::Foo_Conn(this);
	}

Foo::~Foo()
	{
	delete interp;
	}

void Foo::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void Foo::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void Foo::DeliverStream(int len, const u_char* data, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( TCP() && TCP()->IsPartial() )
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		AnalyzerViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void Foo::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
