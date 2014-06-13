
#include "Foo.h"
#include "foo_pac.h"
#include "events.bif.h"

#include <analyzer/protocol/tcp/TCP_Reassembler.h>

using namespace analyzer::Foo;

Foo_Analyzer::Foo_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("Foo", conn)
	{
	interp = new binpac::Foo::Foo_Conn(this);
	}

Foo_Analyzer::~Foo_Analyzer()
	{
	delete interp;
	}

void Foo_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void Foo_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void Foo_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

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

void Foo_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
