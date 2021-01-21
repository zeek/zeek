#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/ssl/events.bif.h"

namespace binpac { namespace SSL { class SSL_Conn; } }

namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace zeek::analyzer::ssl {

class SSL_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit SSL_Analyzer(Connection* conn);
	~SSL_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	void SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig);

	// Tell the analyzer that encryption has started.
	void StartEncryption();
	// Get the TLS version that the server chose. 0 if not yet known.
	uint16_t GetNegotiatedVersion() const;

	// Overriden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SSL_Analyzer(conn); }

protected:
	binpac::SSL::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
	bool had_gap;

};

} // namespace zeek::analyzer::ssl
