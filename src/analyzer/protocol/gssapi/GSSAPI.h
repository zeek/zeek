// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/gssapi/events.bif.h"
#include "zeek/analyzer/protocol/gssapi/gssapi_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::gssapi
	{

class GSSAPI_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{

public:
	explicit GSSAPI_Analyzer(Connection* conn);
	~GSSAPI_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new GSSAPI_Analyzer(conn); }

protected:
	binpac::GSSAPI::GSSAPI_Conn* interp;
	};

	} // namespace zeek::analyzer::gssapi
