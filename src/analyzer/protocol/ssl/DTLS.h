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
	void DeliverPacket(uint64_t len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, uint64_t caplen) override;
	void EndOfData(bool is_orig) override;

	void SendHandshake(uint16_t raw_tls_version, uint8_t msg_type, uint32_t length, const u_char* begin, const u_char* end, bool orig);


	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DTLS_Analyzer(conn); }

protected:
	binpac::DTLS::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
};

} } // namespace analyzer::*

#endif
