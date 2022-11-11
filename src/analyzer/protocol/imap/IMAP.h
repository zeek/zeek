// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// for std::transform
#include <algorithm>

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/imap/imap_pac.h"

namespace zeek::analyzer::imap
	{

class IMAP_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	explicit IMAP_Analyzer(Connection* conn);
	~IMAP_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	void StartTLS();

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new IMAP_Analyzer(conn); }

protected:
	binpac::IMAP::IMAP_Conn* interp;
	bool had_gap;

	bool tls_active;
	};

	} // namespace zeek::analyzer::imap
