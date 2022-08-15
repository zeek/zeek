// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::LinuxSLL2
	{

class LinuxSLL2Analyzer : public Analyzer
	{
public:
	LinuxSLL2Analyzer();
	~LinuxSLL2Analyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<LinuxSLL2Analyzer>();
		}

private:
	// Structure layout is based on https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
	struct SLL2Header
		{
		uint16_t protocol_type;
		uint16_t reserved;
		uint32_t interface_index;
		uint16_t arphrd_type;
		uint8_t packet_type;
		uint8_t addr_len;
		uint64_t addr;
		} __attribute__((__packed__));
	};

	}
