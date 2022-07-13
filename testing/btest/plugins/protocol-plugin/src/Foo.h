
#pragma once

#include "analyzer/protocol/pia/PIA.h"
#include "analyzer/protocol/tcp/TCP.h"

namespace binpac
	{
namespace Foo
	{
class Foo_Conn;
	}
	}

namespace btest::plugin::Demo_Foo
	{

class Foo : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	Foo(zeek::Connection* conn);
	~Foo();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64_t seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn) { return new Foo(conn); }

protected:
	binpac::Foo::Foo_Conn* interp;
	};

	}
