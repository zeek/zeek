// See the file  in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer::geneve
	{

class Geneve_Analyzer final : public analyzer::Analyzer
	{
public:
	explicit Geneve_Analyzer(Connection* conn) : Analyzer("Geneve", conn) { }

	void Done() override;

	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip,
	                   int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new Geneve_Analyzer(conn); }
	};

	} // namespace zeek::analyzer::vxlan
