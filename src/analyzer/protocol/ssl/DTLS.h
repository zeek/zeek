#pragma once

#include "zeek/analyzer/protocol/ssl/events.bif.h"

namespace binpac
	{
namespace DTLS
	{
class SSL_Conn;
	}
	}
namespace binpac
	{
namespace TLSHandshake
	{
class Handshake_Conn;
	}
	}

namespace zeek::analyzer::dtls
	{

class DTLS_Analyzer final : public analyzer::Analyzer
	{
public:
	explicit DTLS_Analyzer(Connection* conn);
	~DTLS_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip,
	                   int caplen) override;
	void EndOfData(bool is_orig) override;

	void SendHandshake(uint16_t raw_tls_version, uint8_t msg_type, uint32_t length,
	                   const u_char* begin, const u_char* end, bool orig);
	// Get the TLS version that the server chose. 0 if not yet known.
	uint16_t GetNegotiatedVersion() const;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new DTLS_Analyzer(conn); }

	/**
	 * Check if the connection is flipped--meaning that the TLS client is the responder of the
	 * connection.
	 *
	 * @return True if connection is flipped.
	 */
	bool GetFlipped();

	/**
	 * Try to decrypt TLS application data from a packet.
	 *
	 * For DTLS, this operation is not currently implemented and this function will
	 * always return false.
	 *
	 **/
	bool TryDecryptApplicationData(int len, const u_char* data, bool is_orig, uint8_t content_type,
	                               uint16_t raw_tls_version);

protected:
	binpac::DTLS::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
	};

	} // namespace zeek::analyzer::dtls
