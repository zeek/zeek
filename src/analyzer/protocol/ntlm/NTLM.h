// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_NTLM_NTLM_H
#define ANALYZER_PROTOCOL_NTLM_NTLM_H

#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"

#include "ntlm_pac.h"

namespace analyzer { namespace ntlm {

class NTLM_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	NTLM_Analyzer(Connection* conn);
	virtual ~NTLM_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new NTLM_Analyzer(conn); }

protected:
	binpac::NTLM::NTLM_Conn* interp;
};

} } // namespace analyzer::*

#endif
