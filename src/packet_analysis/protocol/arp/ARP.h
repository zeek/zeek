// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// clang-format off
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if_arp.h>
// clang-format on

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

#ifndef arp_pkthdr
#define arp_pkthdr arphdr
#endif

namespace zeek::packet_analysis::ARP
	{

class ARPAnalyzer : public Analyzer
	{
public:
	ARPAnalyzer();
	~ARPAnalyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<ARPAnalyzer>();
		}

private:
	zeek::AddrValPtr ToAddrVal(const void* addr, size_t len);
	zeek::StringValPtr ToEthAddrStr(const u_char* addr, size_t len);

	void BadARPEvent(const struct arp_pkthdr* hdr, const char* fmt, ...)
		__attribute__((format(printf, 3, 4)));
	void RequestReplyEvent(EventHandlerPtr e, const u_char* src, const u_char* dst,
	                       const struct arp_pkthdr* hdr);
	};

	}
