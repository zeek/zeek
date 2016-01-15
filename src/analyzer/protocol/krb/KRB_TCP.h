// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_KRB_KRB_TCP_H
#define ANALYZER_PROTOCOL_KRB_KRB_TCP_H

#include "analyzer/protocol/tcp/TCP.h"

#include "krb_TCP_pac.h"

namespace analyzer { namespace krb_tcp {

class KRB_Analyzer : public tcp::TCP_ApplicationAnalyzer {

public:
	KRB_Analyzer(Connection* conn);
	virtual ~KRB_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new KRB_Analyzer(conn); }

protected:
	binpac::KRB_TCP::KRB_Conn* interp;
	bool had_gap;
};

} } // namespace analyzer::*

#endif
