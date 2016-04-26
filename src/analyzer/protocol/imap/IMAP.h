// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_IMAP_IMAP_H
#define ANALYZER_PROTOCOL_IMAP_IMAP_H

// for std::transform
#include <algorithm>
#include "analyzer/protocol/tcp/TCP.h"

#include "imap_pac.h"

namespace analyzer { namespace imap {

class IMAP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	IMAP_Analyzer(Connection* conn);
	virtual ~IMAP_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);

	void StartTLS();

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new IMAP_Analyzer(conn); }

protected:
	binpac::IMAP::IMAP_Conn* interp;
	bool had_gap;

	bool tls_active;
};

} } // namespace analyzer::*

#endif /* ANALYZER_PROTOCOL_IMAP_IMAP_H */
