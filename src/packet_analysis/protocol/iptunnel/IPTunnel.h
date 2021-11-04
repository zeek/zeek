// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IPAddr.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::IPTunnel
	{

namespace detail
	{
class IPTunnelTimer;
	}

class IPTunnelAnalyzer : public Analyzer
	{
public:
	IPTunnelAnalyzer();
	~IPTunnelAnalyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<IPTunnelAnalyzer>();
		}

	/**
	 * Wrapper that handles encapsulated IP packets and passes them back into
	 * packet analysis.
	 *
	 * @param t Network time.
	 * @param pkt If the outer pcap header is available, this pointer can be set
	 *        so the fake pcap header passed to the next analyzer will use the
	 *        same timeval. The caplen and len fields of the fake pcap header
	 *        are always set to the TotalLength() of \a inner.
	 * @param inner Pointer to IP header wrapper of the inner packet, ownership
	 *        of the pointer's memory is assumed by this function.
	 * @param prev Any previous encapsulation stack of the caller, not including
	 *        the most-recently found depth of encapsulation.
	 * @param ec The most-recently found depth of encapsulation.
	 */
	bool ProcessEncapsulatedPacket(double t, const Packet* pkt,
	                               const std::unique_ptr<IP_Hdr>& inner,
	                               std::shared_ptr<EncapsulationStack> prev,
	                               const EncapsulatingConn& ec);

	/**
	 * Wrapper that handles encapsulated Ethernet/IP packets and passes them back into
	 * packet analysis.
	 *
	 * @param t Network time.
	 * @param pkt If the outer pcap header is available, this pointer can be set
	 *        so the fake pcap header passed to the next analyzer will use the
	 *        same timeval.
	 * @param caplen Number of captured bytes remaining
	 * @param len Number of bytes remaining as claimed by outer framing
	 * @param data The remaining packet data
	 * @param link_type Layer 2 link type used for initializing inner packet
	 * @param prev Any previous encapsulation stack of the caller, not
	 *        including the most-recently found depth of encapsulation.
	 * @param ec The most-recently found depth of encapsulation.
	 */
	bool ProcessEncapsulatedPacket(double t, const Packet* pkt, uint32_t caplen, uint32_t len,
	                               const u_char* data, int link_type,
	                               std::shared_ptr<EncapsulationStack> prev,
	                               const EncapsulatingConn& ec);

protected:
	friend class detail::IPTunnelTimer;

	using IPPair = std::pair<IPAddr, IPAddr>;
	using TunnelActivity = std::pair<EncapsulatingConn, double>;
	using IPTunnelMap = std::map<IPPair, TunnelActivity>;
	IPTunnelMap ip_tunnels;
	};

namespace detail
	{

class IPTunnelTimer final : public zeek::detail::Timer
	{
public:
	IPTunnelTimer(double t, IPTunnelAnalyzer::IPPair p, IPTunnelAnalyzer* analyzer);
	~IPTunnelTimer() override = default;

	void Dispatch(double t, bool is_expire) override;

protected:
	IPTunnelAnalyzer::IPPair tunnel_idx;
	IPTunnelAnalyzer* analyzer;
	};

	} // namespace detail

// This is temporary until the TCP and UDP analyzers are moved to be packet analyzers.
extern IPTunnelAnalyzer* ip_tunnel_analyzer;

	}
