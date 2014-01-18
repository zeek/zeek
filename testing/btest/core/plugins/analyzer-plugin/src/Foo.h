
#ifndef BRO_PLUGIN_DEMO_FOO_H
#define BRO_PLUGIN_DEMO_FOO_H

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"

namespace binpac  { namespace Foo { class Foo_Conn; } }

namespace analyzer { namespace Foo {

class Foo_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	Foo_Analyzer(Connection* conn);
	~Foo_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Foo_Analyzer(conn); }

protected:
	binpac::Foo::Foo_Conn* interp;
};

} } // namespace analyzer::* 

#endif
