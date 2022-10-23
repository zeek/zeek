#ifndef ANALYZER_PROTOCOL_FOO_FOO_H
#define ANALYZER_PROTOCOL_FOO_FOO_H

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "foo.bif.h"
#include "foo_pac.h"

namespace btest::analyzer::FOO
	{

class FOO_Analyzer : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	FOO_Analyzer(zeek::Connection* conn);
	virtual ~FOO_Analyzer();

	// Overridden from Analyzer.
	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64_t seq, int len, bool orig);

	// Overridden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	static zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
		{
		return new FOO_Analyzer(conn);
		}

protected:
	binpac::FOO::FOO_Conn* interp;
	bool had_gap;
	};

	} // namespace btest::analyzer::FOO

#endif
