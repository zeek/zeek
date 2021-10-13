// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Frag.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::detail
	{
class Discarder;
	}

namespace zeek::packet_analysis::IP
	{

class IPAnalyzer : public Analyzer
	{
public:
	IPAnalyzer();
	~IPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<IPAnalyzer>();
		}

private:
	// Returns a reassembled packet, or nil if there are still
	// some missing fragments.
	zeek::detail::FragReassembler* NextFragment(double t, const IP_Hdr* ip, const u_char* pkt);

	zeek::detail::Discarder* discarder = nullptr;
	};

/**
 * Returns a wrapper IP_Hdr object if \a pkt appears to be a valid IPv4
 * or IPv6 header based on whether it's long enough to contain such a header,
 * if version given in the header matches the proto argument, and also checks
 * that the payload length field of that header matches the actual
 * length of \a pkt given by \a caplen.
 *
 * @param caplen The length of \a pkt in bytes.
 * @param pkt The inner IP packet data.
 * @param proto Either IPPROTO_IPV6 or IPPROTO_IPV4 to indicate which IP
 *        protocol \a pkt corresponds to.
 * @param inner The inner IP packet wrapper pointer to be allocated/assigned
 *        if \a pkt looks like a valid IP packet or at least long enough
 *        to hold an IP header.
 * @return 0 If the inner IP packet appeared valid, else -1 if \a caplen
 *         is greater than the supposed IP packet's payload length field, -2
 *         if the version of the inner header does not match proto or
 *         1 if \a caplen is less than the supposed packet's payload length.
 *         In the -1 case, \a inner may still be non-null if \a caplen was
 *         long enough to be an IP header, and \a inner is always non-null
 *         for other return values.
 */
int ParsePacket(int caplen, const u_char* const pkt, int proto, std::unique_ptr<IP_Hdr>& inner);
	}
