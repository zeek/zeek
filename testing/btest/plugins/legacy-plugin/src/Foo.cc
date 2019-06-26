
#include "Foo.h"
#include "foo_pac.h"
#include "events.bif.h"

#include <analyzer/protocol/tcp/TCP_Reassembler.h>

using namespace plugin::Demo_Foo;

Foo::Foo(Connection* conn)
    : analyzer::tcp::TCP_ApplicationAnalyzer("Foo", conn)
	{
	interp = new binpac::Foo::Foo_Conn(this);
	}

Foo::~Foo()
	{
	delete interp;
	}

void Foo::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void Foo::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void Foo::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void Foo::Undelivered(uint64 seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
