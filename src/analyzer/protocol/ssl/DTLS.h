#ifndef ANALYZER_PROTOCOL_SSL_DTLS_H
#define ANALYZER_PROTOCOL_SSL_DTLS_H

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"

namespace binpac { namespace DTLS { class SSL_Conn; } }

namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace analyzer { namespace dtls {

class DTLS_Analyzer : public analyzer::Analyzer {
public:
	DTLS_Analyzer(Connection* conn);
	virtual ~DTLS_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);
	virtual void EndOfData(bool is_orig);

	void SendHandshake(uint8 msg_type, uint32 length, const u_char* begin, const u_char* end, bool orig);


	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DTLS_Analyzer(conn); }

protected:
	binpac::DTLS::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
};

} } // namespace analyzer::*

#endif
