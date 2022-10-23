// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/mysql/events.bif.h"
#include "zeek/analyzer/protocol/mysql/mysql_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::mysql
	{

class MySQL_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{

public:
	explicit MySQL_Analyzer(Connection* conn);
	~MySQL_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new MySQL_Analyzer(conn); }

protected:
	binpac::MySQL::MySQL_Conn* interp;
	bool had_gap;
	};

	} // namespace zeek::analyzer::mysql
