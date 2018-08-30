#ifndef ANALYZER_PROTOCOL_SSL_DTLS_H
#define ANALYZER_PROTOCOL_SSL_DTLS_H

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"

namespace binpac { namespace DTLS { class SSL_Conn; } }

namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace analyzer { namespace dtls {

class DTLS_Analyzer : public analyzer::Analyzer {
public:
	explicit DTLS_Analyzer(Connection* conn);
	~DTLS_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen) override;
	void EndOfData(bool is_orig) override;

	void SendHandshake(uint16 raw_tls_version, uint8 msg_type, uint32 length, const u_char* begin, const u_char* end, bool orig);


	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DTLS_Analyzer(conn); }

protected:
	binpac::DTLS::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
};

} } // namespace analyzer::*

#endif
