// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

#include <pcap.h> // For DLT_ constants

#include "zeek/Sessions.h"
#include "zeek/RunState.h"
#include "zeek/IP.h"
#include "zeek/TunnelEncapsulation.h"

namespace zeek::packet_analysis::IPTunnel {

IPTunnelAnalyzer* ip_tunnel_analyzer;

IPTunnelAnalyzer::IPTunnelAnalyzer()
	: zeek::packet_analysis::Analyzer("IPTunnel")
	{
	ip_tunnel_analyzer = this;
	}

bool IPTunnelAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! packet->ip_hdr )
		{
		reporter->InternalError("IPTunnelAnalyzer: ip_hdr not found in packet keystore");
		return false;
		}

	if ( ! BifConst::Tunnel::enable_ip )
		{
		Weird("IP_tunnel", packet);
		return false;
		}

	if ( packet->encap &&
	     packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	int proto = packet->proto;
	int gre_version = packet->gre_version;
	BifEnum::Tunnel::Type tunnel_type = packet->tunnel_type;
	int gre_link_type = packet->gre_link_type;

	IP_Hdr* inner = nullptr;

	if ( gre_version != 0 )
		{
		// Check for a valid inner packet first.
		int result = sessions->ParseIPPacket(len, data, proto, inner);
		if ( result == -2 )
			Weird("invalid_inner_IP_version", packet);
		else if ( result < 0 )
			Weird("truncated_inner_IP", packet);
		else if ( result > 0 )
			Weird("inner_IP_payload_length_mismatch", packet);

		if ( result != 0 )
			{
			delete inner;
			return false;
			}
		}

	// Look up to see if we've already seen this IP tunnel, identified
	// by the pair of IP addresses, so that we can always associate the
	// same UID with it.
	IPPair tunnel_idx;
	if ( packet->ip_hdr->SrcAddr() < packet->ip_hdr->DstAddr() )
		tunnel_idx = IPPair(packet->ip_hdr->SrcAddr(), packet->ip_hdr->DstAddr());
	else
		tunnel_idx = IPPair(packet->ip_hdr->DstAddr(), packet->ip_hdr->SrcAddr());

	IPTunnelMap::iterator tunnel_it = ip_tunnels.find(tunnel_idx);

	if ( tunnel_it == ip_tunnels.end() )
		{
		EncapsulatingConn ec(packet->ip_hdr->SrcAddr(), packet->ip_hdr->DstAddr(),
		                     tunnel_type);
		ip_tunnels[tunnel_idx] = TunnelActivity(ec, run_state::network_time);
		zeek::detail::timer_mgr->Add(new detail::IPTunnelTimer(run_state::network_time, tunnel_idx, this));
		}
	else
		tunnel_it->second.second = zeek::run_state::network_time;

	if ( gre_version == 0 )
		ProcessEncapsulatedPacket(run_state::processing_start_time, packet, len, len, data, gre_link_type,
		                          packet->encap, ip_tunnels[tunnel_idx].first);
	else
		ProcessEncapsulatedPacket(run_state::processing_start_time, packet, inner, packet->encap,
		                          ip_tunnels[tunnel_idx].first);

	return true;
	}

/**
 * Handles a packet that contains an IP header directly after the tunnel header.
 */
bool IPTunnelAnalyzer::ProcessEncapsulatedPacket(double t, const Packet* pkt,
                                                 const IP_Hdr* inner,
                                                 std::shared_ptr<EncapsulationStack> prev,
                                                 const EncapsulatingConn& ec)
	{
	uint32_t caplen, len;
	caplen = len = inner->TotalLen();

	pkt_timeval ts;
	int link_type;

	if ( pkt )
		ts = pkt->ts;
	else
		{
		ts.tv_sec = (time_t) run_state::network_time;
		ts.tv_usec = (suseconds_t)
		    ((run_state::network_time - (double)ts.tv_sec) * 1000000);
		}

	const u_char* data = nullptr;

	if ( inner->IP4_Hdr() )
		data = (const u_char*) inner->IP4_Hdr();
	else
		data = (const u_char*) inner->IP6_Hdr();

	auto outer = prev ? prev : std::make_shared<EncapsulationStack>();
	outer->Add(ec);

	// Construct fake packet containing the inner packet so it can be processed
	// like a normal one.
	Packet p;
	p.Init(DLT_RAW, &ts, caplen, len, data, false, "");
	p.encap = outer;

	// Forward the packet back to the IP analyzer.
	bool return_val = ForwardPacket(len, data, &p);

	delete inner;

	return return_val;
	}

/**
 * Handles a packet that contains a physical-layer header after the tunnel header.
 */
bool IPTunnelAnalyzer::ProcessEncapsulatedPacket(double t, const Packet* pkt,
                                                 uint32_t caplen, uint32_t len,
                                                 const u_char* data, int link_type,
                                                 std::shared_ptr<EncapsulationStack> prev,
                                                 const EncapsulatingConn& ec)
	{
	pkt_timeval ts;

	if ( pkt )
		ts = pkt->ts;
	else
		{
		ts.tv_sec = (time_t) run_state::network_time;
		ts.tv_usec = (suseconds_t)
		    ((run_state::network_time - (double)ts.tv_sec) * 1000000);
		}

	auto outer = prev ? prev : std::make_shared<EncapsulationStack>();
	outer->Add(ec);

	// Construct fake packet containing the inner packet so it can be processed
	// like a normal one.
	Packet p;
	p.Init(link_type, &ts, caplen, len, data, false, "");
	p.encap = outer;

	// Process the packet as if it was a brand new packet by passing it back
	// to the packet manager.
	bool return_val = packet_mgr->ProcessInnerPacket(&p);

	return return_val;
	}

namespace detail {

IPTunnelTimer::IPTunnelTimer(double t, IPTunnelAnalyzer::IPPair p, IPTunnelAnalyzer* analyzer)
	: Timer(t + BifConst::Tunnel::ip_tunnel_timeout,
	        zeek::detail::TIMER_IP_TUNNEL_INACTIVITY),
	  tunnel_idx(p), analyzer(analyzer)
	{
	}

void IPTunnelTimer::Dispatch(double t, bool is_expire)
	{
	IPTunnelAnalyzer::IPTunnelMap::const_iterator it =
		analyzer->ip_tunnels.find(tunnel_idx);

	if ( it == analyzer->ip_tunnels.end() )
		return;

	double last_active = it->second.second;
	double inactive_time = t > last_active ? t - last_active : 0;

	if ( inactive_time >= BifConst::Tunnel::ip_tunnel_timeout )
		// tunnel activity timed out, delete it from map
		analyzer->ip_tunnels.erase(tunnel_idx);

	else if ( ! is_expire )
		// tunnel activity didn't timeout, schedule another timer
		zeek::detail::timer_mgr->Add(new IPTunnelTimer(t, tunnel_idx, analyzer));
	}

} // namespace detail

} // namespace zeek::packet_analysis::IPTunnel
