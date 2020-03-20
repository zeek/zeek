#ifndef ANALYZER_PROTOCOL_FOO_FOO_H
#define ANALYZER_PROTOCOL_FOO_FOO_H

#include "foo.bif.h"

#include "analyzer/protocol/tcp/TCP.h"

#include "foo_pac.h"

namespace analyzer { namespace FOO {

class FOO_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	FOO_Analyzer(Connection* conn);
	virtual ~FOO_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64_t seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new FOO_Analyzer(conn); }

protected:
	binpac::FOO::FOO_Conn* interp;
	bool had_gap;

};

} } // namespace analyzer::FOO

#endif
