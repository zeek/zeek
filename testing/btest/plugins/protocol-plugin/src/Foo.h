
#ifndef BRO_PLUGIN_DEMO_FOO_H
#define BRO_PLUGIN_DEMO_FOO_H

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"

namespace binpac  { namespace Foo { class Foo_Conn; } }

namespace plugin {
namespace Demo_Foo {

class Foo : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	Foo(Connection* conn);
	~Foo();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Foo(conn); }

protected:
	binpac::Foo::Foo_Conn* interp;
};

} }

#endif
