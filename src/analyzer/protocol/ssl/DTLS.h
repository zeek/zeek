#ifndef ANALYZER_PROTOCOL_SSL_DTLS_H
#define ANALYZER_PROTOCOL_SSL_DTLS_H

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"
#include "dtls_pac.h"

namespace analyzer { namespace dtls {

class DTLS_Analyzer : public analyzer::Analyzer {
public:
	DTLS_Analyzer(Connection* conn);
	virtual ~DTLS_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);


	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DTLS_Analyzer(conn); }

protected:
	binpac::DTLS::SSL_Conn* interp;
};

} } // namespace analyzer::*

#endif
