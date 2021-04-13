// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace zeek::packet_analysis::ICMP {

class ICMPAnalyzer final : public IP::IPBasedAnalyzer {
public:
	ICMPAnalyzer();
	~ICMPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<ICMPAnalyzer>();
		}

	void CreateTransportAnalyzer(Connection* conn, IP::IPBasedTransportAnalyzer*& root,
	                             analyzer::pia::PIA*& pia, bool& check_port) override;

protected:

	void ContinueProcessing(Connection* c, double t, bool is_orig, int remaining,
	                        Packet* pkt) override;

private:

	// Returns the counterpart type to the given type (e.g., the counterpart
	// to ICMP_ECHOREPLY is ICMP_ECHO).
	int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way);
	int ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way);

};

}
