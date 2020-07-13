// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>

namespace zeek::packet_analysis::LinuxSLL {

class LinuxSLLAnalyzer : public Analyzer {
public:
	LinuxSLLAnalyzer();
	~LinuxSLLAnalyzer() override = default;

	std::tuple<AnalyzerResult, identifier_t> Analyze(Packet* packet) override;

	static Analyzer* Instantiate()
		{
		return new LinuxSLLAnalyzer();
		}

private:

	// Structure layout is based on https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
	struct SLLHeader
		{
		uint16_t packet_type;
		uint16_t arphrd_type;
		uint16_t addr_len;
		uint64_t addr;
		uint16_t protocol_type;
		} __attribute__((__packed__));
};

}
