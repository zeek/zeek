// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/xmpp/xmpp_pac.h"

namespace zeek::analyzer::xmpp
	{

class XMPP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	explicit XMPP_Analyzer(Connection* conn);
	~XMPP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	void StartTLS();

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new XMPP_Analyzer(conn); }

protected:
	std::unique_ptr<binpac::XMPP::XMPP_Conn> interp;
	bool had_gap;

	bool tls_active;
	};

	} // namespace zeek::analyzer::xmpp
