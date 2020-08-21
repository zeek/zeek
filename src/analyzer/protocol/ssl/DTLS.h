#pragma once

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"

namespace binpac { namespace DTLS { class SSL_Conn; } }
namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace zeek::analyzer::dtls {

class DTLS_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit DTLS_Analyzer(zeek::Connection* conn);
	~DTLS_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;
	void EndOfData(bool is_orig) override;

	void SendHandshake(uint16_t raw_tls_version, uint8_t msg_type, uint32_t length, const u_char* begin, const u_char* end, bool orig);


	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new DTLS_Analyzer(conn); }

protected:
	binpac::DTLS::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
};

} // namespace zeek::analyzer::dtls

namespace analyzer::dtls {

using DTLS_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::dtls::DTLS_Analyzer.")]] = zeek::analyzer::dtls::DTLS_Analyzer;

} // namespace analyzer::dtls
