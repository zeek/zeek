#pragma once

#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "zeek/analyzer/protocol/ssl/events.bif.h"

namespace binpac { namespace SSL { class SSL_Conn; } }

namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace zeek::analyzer::ssl {

class SSL_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit SSL_Analyzer(Connection* conn);
	~SSL_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	void SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig);

	// Tell the analyzer that encryption has started.
	void StartEncryption();
	// Get the TLS version that the server chose. 0 if not yet known.
	uint16_t GetNegotiatedVersion() const;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SSL_Analyzer(conn); }

	// Key material for decryption
	void SetSecret(const u_char* data, int len);
	void SetKeys(const u_char* data, int len);

	bool TryDecryptApplicationData(int len, const u_char* data, bool is_orig, uint8_t content_type, uint16_t raw_tls_version);
	bool TLS12_PRF(const std::string& secret, const std::string& label, const char* rnd1, size_t rnd1_len, const char* rnd2, size_t rnd2_len, u_char* out, size_t out_len);
	void ForwardDecryptedData(int len, const u_char* data, bool is_orig);

protected:
	binpac::SSL::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
	bool had_gap;

	// FIXME: should this be moved into the connection?
	int c_seq;
	int s_seq;
	StringValPtr secret;
	StringValPtr keys;
	zeek::analyzer::pia::PIA_TCP *pia;
};

} // namespace zeek::analyzer::ssl
