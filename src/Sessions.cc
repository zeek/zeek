// See the file "COPYING" in the main distribution directory for copyright.


#include "zeek-config.h"
#include "Sessions.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>

#include "Desc.h"
#include "Net.h"
#include "Event.h"
#include "Timer.h"
#include "NetVar.h"
#include "Reporter.h"

#include "analyzer/protocol/icmp/ICMP.h"
#include "analyzer/protocol/udp/UDP.h"

#include "analyzer/protocol/stepping-stone/SteppingStone.h"
#include "analyzer/protocol/stepping-stone/events.bif.h"
#include "analyzer/protocol/arp/ARP.h"
#include "analyzer/protocol/arp/events.bif.h"
#include "Discard.h"
#include "RuleMatcher.h"

#include "TunnelEncapsulation.h"

#include "analyzer/Manager.h"
#include "iosource/IOSource.h"
#include "iosource/PktDumper.h"

// These represent NetBIOS services on ephemeral ports.  They're numbered
// so that we can use a single int to hold either an actual TCP/UDP server
// port or one of these.
enum NetBIOS_Service {
	NETBIOS_SERVICE_START = 0x10000L,	// larger than any port
	NETBIOS_SERVICE_DCE_RPC,
};

NetSessions* sessions;

void IPTunnelTimer::Dispatch(double t, int is_expire)
	{
	NetSessions::IPTunnelMap::const_iterator it =
			sessions->ip_tunnels.find(tunnel_idx);

	if ( it == sessions->ip_tunnels.end() )
		return;

	double last_active = it->second.second;
	double inactive_time = t > last_active ? t - last_active : 0;

	if ( inactive_time >= BifConst::Tunnel::ip_tunnel_timeout )
		// tunnel activity timed out, delete it from map
		sessions->ip_tunnels.erase(tunnel_idx);

	else if ( ! is_expire )
		// tunnel activity didn't timeout, schedule another timer
		timer_mgr->Add(new IPTunnelTimer(t, tunnel_idx));
	}

NetSessions::NetSessions()
	{
	if ( stp_correlate_pair )
		stp_manager = new analyzer::stepping_stone::SteppingStoneManager();
	else
		stp_manager = 0;

	discarder = new Discarder();
	if ( ! discarder->IsActive() )
		{
		delete discarder;
		discarder = 0;
		}

	packet_filter = 0;

	dump_this_packet = 0;
	num_packets_processed = 0;

	if ( pkt_profile_mode && pkt_profile_freq > 0 && pkt_profile_file )
		pkt_profiler = new PacketProfiler(pkt_profile_mode,
				pkt_profile_freq, pkt_profile_file->AsFile());
	else
		pkt_profiler = 0;

	if ( arp_request || arp_reply || bad_arp )
		arp_analyzer = new analyzer::arp::ARP_Analyzer();
	else
		arp_analyzer = 0;

	memset(&stats, 0, sizeof(SessionStats));
	}

NetSessions::~NetSessions()
	{
	delete packet_filter;
	delete pkt_profiler;
	Unref(arp_analyzer);
	delete discarder;
	delete stp_manager;

	for ( const auto& entry : tcp_conns )
		Unref(entry.second);
	for ( const auto& entry : udp_conns )
		Unref(entry.second);
	for ( const auto& entry : icmp_conns )
		Unref(entry.second);
	for ( const auto& entry : fragments )
		Unref(entry.second);
	}

void NetSessions::Done()
	{
	}

void NetSessions::NextPacket(double t, const Packet* pkt)
	{
	SegmentProfiler prof(segment_logger, "dispatching-packet");

	if ( raw_packet )
		mgr.QueueEventFast(raw_packet, {pkt->BuildPktHdrVal()});

	if ( pkt_profiler )
		pkt_profiler->ProfilePkt(t, pkt->cap_len);

	++num_packets_processed;

	dump_this_packet = 0;

	if ( record_all_packets )
		DumpPacket(pkt);

	if ( pkt->hdr_size > pkt->cap_len )
		{
		Weird("truncated_link_frame", pkt);
		return;
		}

	uint32_t caplen = pkt->cap_len - pkt->hdr_size;

	if ( pkt->l3_proto == L3_IPV4 )
		{
		if ( caplen < sizeof(struct ip) )
			{
			Weird("truncated_IP", pkt);
			return;
			}

		const struct ip* ip = (const struct ip*) (pkt->data + pkt->hdr_size);
		IP_Hdr ip_hdr(ip, false);
		DoNextPacket(t, pkt, &ip_hdr, 0);
		}

	else if ( pkt->l3_proto == L3_IPV6 )
		{
		if ( caplen < sizeof(struct ip6_hdr) )
			{
			Weird("truncated_IP", pkt);
			return;
			}

		IP_Hdr ip_hdr((const struct ip6_hdr*) (pkt->data + pkt->hdr_size), false, caplen);
		DoNextPacket(t, pkt, &ip_hdr, 0);
		}

	else if ( pkt->l3_proto == L3_ARP )
		{
		if ( arp_analyzer )
			arp_analyzer->NextPacket(t, pkt);
		}

	else
		{
		Weird("unknown_packet_type", pkt);
		return;
		}


	if ( dump_this_packet && ! record_all_packets )
		DumpPacket(pkt);
	}

static unsigned int gre_header_len(uint16_t flags)
	{
	unsigned int len = 4;  // Always has 2 byte flags and 2 byte protocol type.

	if ( flags & 0x8000 )
		// Checksum/Reserved1 present.
		len += 4;

	// Not considering routing presence bit since it's deprecated ...

	if ( flags & 0x2000 )
		// Key present.
		len += 4;

	if ( flags & 0x1000 )
		// Sequence present.
		len += 4;

	if ( flags & 0x0080 )
		// Acknowledgement present.
		len += 4;

	return len;
	}

void NetSessions::DoNextPacket(double t, const Packet* pkt, const IP_Hdr* ip_hdr,
			       const EncapsulationStack* encapsulation)
	{
	uint32_t caplen = pkt->cap_len - pkt->hdr_size;
	const struct ip* ip4 = ip_hdr->IP4_Hdr();

	uint32_t len = ip_hdr->TotalLen();
	if ( len == 0 )
		{
		// TCP segmentation offloading can zero out the ip_len field.
		Weird("ip_hdr_len_zero", pkt, encapsulation);

		// Cope with the zero'd out ip_len field by using the caplen.
		len = pkt->cap_len - pkt->hdr_size;
		}

	if ( pkt->len < len + pkt->hdr_size )
		{
		Weird("truncated_IP", pkt, encapsulation);
		return;
		}

	// For both of these it is safe to pass ip_hdr because the presence
	// is guaranteed for the functions that pass data to us.
	uint16_t ip_hdr_len = ip_hdr->HdrLen();
	if ( ip_hdr_len > len )
		{
		Weird("invalid_IP_header_size", ip_hdr, encapsulation);
		return;
		}

	if ( ip_hdr_len > caplen )
		{
		Weird("internally_truncated_header", ip_hdr, encapsulation);
		return;
		}

	// Ignore if packet matches packet filter.
	if ( packet_filter && packet_filter->Match(ip_hdr, len, caplen) )
		 return;

	if ( ! ignore_checksums && ip4 &&
	     ones_complement_checksum((void*) ip4, ip_hdr_len, 0) != 0xffff )
		{
		Weird("bad_IP_checksum", pkt, encapsulation);
		return;
		}

	if ( discarder && discarder->NextPacket(ip_hdr, len, caplen) )
		return;

	FragReassembler* f = 0;

	if ( ip_hdr->IsFragment() )
		{
		dump_this_packet = 1;	// always record fragments

		if ( caplen < len )
			{
			Weird("incompletely_captured_fragment", ip_hdr, encapsulation);

			// Don't try to reassemble, that's doomed.
			// Discard all except the first fragment (which
			// is useful in analyzing header-only traces)
			if ( ip_hdr->FragOffset() != 0 )
				return;
			}
		else
			{
			f = NextFragment(t, ip_hdr, pkt->data + pkt->hdr_size);
			const IP_Hdr* ih = f->ReassembledPkt();
			if ( ! ih )
				// It didn't reassemble into anything yet.
				return;

			ip4 = ih->IP4_Hdr();
			ip_hdr = ih;

			caplen = len = ip_hdr->TotalLen();
			ip_hdr_len = ip_hdr->HdrLen();

			if ( ip_hdr_len > len )
				{
				Weird("invalid_IP_header_size", ip_hdr, encapsulation);
				return;
				}
			}
		}

	FragReassemblerTracker frt(this, f);

	len -= ip_hdr_len;	// remove IP header
	caplen -= ip_hdr_len;

	// We stop building the chain when seeing IPPROTO_ESP so if it's
	// there, it's always the last.
	if ( ip_hdr->LastHeader() == IPPROTO_ESP )
		{
		dump_this_packet = 1;
		if ( esp_packet )
			mgr.QueueEventFast(esp_packet, {ip_hdr->BuildPktHdrVal()});

		// Can't do more since upper-layer payloads are going to be encrypted.
		return;
		}

#ifdef ENABLE_MOBILE_IPV6
	// We stop building the chain when seeing IPPROTO_MOBILITY so it's always
	// last if present.
	if ( ip_hdr->LastHeader() == IPPROTO_MOBILITY )
		{
		dump_this_packet = 1;

		if ( ! ignore_checksums && mobility_header_checksum(ip_hdr) != 0xffff )
			{
			Weird("bad_MH_checksum", pkt, encapsulation);
			return;
			}

		if ( mobile_ipv6_message )
			mgr.QueueEvent(mobile_ipv6_message, {ip_hdr->BuildPktHdrVal()});

		if ( ip_hdr->NextProto() != IPPROTO_NONE )
			Weird("mobility_piggyback", pkt, encapsulation);

		return;
		}
#endif
	int proto = ip_hdr->NextProto();

	if ( CheckHeaderTrunc(proto, len, caplen, pkt, encapsulation) )
		return;

	const u_char* data = ip_hdr->Payload();

	ConnID id;
	id.src_addr = ip_hdr->SrcAddr();
	id.dst_addr = ip_hdr->DstAddr();
	ConnectionMap* d = nullptr;
	BifEnum::Tunnel::Type tunnel_type = BifEnum::Tunnel::IP;

	switch ( proto ) {
	case IPPROTO_TCP:
		{
		const struct tcphdr* tp = (const struct tcphdr *) data;
		id.src_port = tp->th_sport;
		id.dst_port = tp->th_dport;
		id.is_one_way = 0;
		d = &tcp_conns;
		break;
		}

	case IPPROTO_UDP:
		{
		const struct udphdr* up = (const struct udphdr *) data;
		id.src_port = up->uh_sport;
		id.dst_port = up->uh_dport;
		id.is_one_way = 0;
		d = &udp_conns;
		break;
		}

	case IPPROTO_ICMP:
		{
		const struct icmp* icmpp = (const struct icmp *) data;

		id.src_port = icmpp->icmp_type;
		id.dst_port = analyzer::icmp::ICMP4_counterpart(icmpp->icmp_type,
								icmpp->icmp_code,
								id.is_one_way);

		id.src_port = htons(id.src_port);
		id.dst_port = htons(id.dst_port);

		d = &icmp_conns;
		break;
		}

	case IPPROTO_ICMPV6:
		{
		const struct icmp* icmpp = (const struct icmp *) data;

		id.src_port = icmpp->icmp_type;
		id.dst_port = analyzer::icmp::ICMP6_counterpart(icmpp->icmp_type,
								icmpp->icmp_code,
								id.is_one_way);

		id.src_port = htons(id.src_port);
		id.dst_port = htons(id.dst_port);

		d = &icmp_conns;
		break;
		}

	case IPPROTO_GRE:
		{
		if ( ! BifConst::Tunnel::enable_gre )
			{
			Weird("GRE_tunnel", ip_hdr, encapsulation);
			return;
			}

		uint16_t flags_ver = ntohs(*((uint16_t*)(data + 0)));
		uint16_t proto_typ = ntohs(*((uint16_t*)(data + 2)));
		int gre_version = flags_ver & 0x0007;

		// If a carried packet has ethernet, this will help skip it.
		unsigned int eth_len = 0;
		unsigned int gre_len = gre_header_len(flags_ver);
		unsigned int ppp_len = gre_version == 1 ? 4 : 0;
		unsigned int erspan_len = 0;

		if ( gre_version != 0 && gre_version != 1 )
			{
			Weird("unknown_gre_version", ip_hdr, encapsulation,
			      fmt("%d", gre_version));
			return;
			}

		if ( gre_version == 0 )
			{
			if ( proto_typ == 0x6558 )
				{
				// transparent ethernet bridging
				if ( len > gre_len + 14 )
					{
					eth_len = 14;
					proto_typ = ntohs(*((uint16_t*)(data + gre_len + eth_len - 2)));
					}
				else
					{
					Weird("truncated_GRE", ip_hdr, encapsulation);
					return;
					}
				}

			else if ( proto_typ == 0x88be )
				{
				// ERSPAN type II
				if ( len > gre_len + 14 + 8 )
					{
					erspan_len = 8;
					eth_len = 14;
					proto_typ = ntohs(*((uint16_t*)(data + gre_len + erspan_len + eth_len - 2)));
					}
				else
					{
					Weird("truncated_GRE", ip_hdr, encapsulation);
					return;
					}
				}

			else if ( proto_typ == 0x22eb )
				{
				// ERSPAN type III
				if ( len > gre_len + 14 + 12 )
					{
					erspan_len = 12;
					eth_len = 14;

					auto flags = data + erspan_len - 1;
					bool have_opt_header = ((*flags & 0x01) == 0x01);

					if ( have_opt_header  )
						{
						if ( len > gre_len + erspan_len + 8 + eth_len )
							erspan_len += 8;
						else
							{
							Weird("truncated_GRE", ip_hdr, encapsulation);
							return;
							}
						}

					proto_typ = ntohs(*((uint16_t*)(data + gre_len + erspan_len + eth_len - 2)));
					}
				else
					{
					Weird("truncated_GRE", ip_hdr, encapsulation);
					return;
					}
				}

			if ( proto_typ == 0x0800 )
				proto = IPPROTO_IPV4;
			else if ( proto_typ == 0x86dd )
				proto = IPPROTO_IPV6;
			else
				{
				// Not IPv4/IPv6 payload.
				Weird("unknown_gre_protocol", ip_hdr, encapsulation,
				      fmt("%d", proto_typ));
				return;
				}

			}

		else // gre_version == 1
			{
			if ( proto_typ != 0x880b )
				{
				// Enhanced GRE payload must be PPP.
				Weird("egre_protocol_type", ip_hdr, encapsulation,
				      fmt("%d", proto_typ));
				return;
				}
			}

		if ( flags_ver & 0x4000 )
			{
			// RFC 2784 deprecates the variable length routing field
			// specified by RFC 1701. It could be parsed here, but easiest
			// to just skip for now.
			Weird("gre_routing", ip_hdr, encapsulation);
			return;
			}

		if ( flags_ver & 0x0078 )
			{
			// Expect last 4 bits of flags are reserved, undefined.
			Weird("unknown_gre_flags", ip_hdr, encapsulation);
			return;
			}

		if ( len < gre_len + ppp_len + eth_len + erspan_len || caplen < gre_len + ppp_len + eth_len + erspan_len )
			{
			Weird("truncated_GRE", ip_hdr, encapsulation);
			return;
			}

		if ( gre_version == 1 )
			{
			uint16_t ppp_proto = ntohs(*((uint16_t*)(data + gre_len + 2)));

			if ( ppp_proto != 0x0021 && ppp_proto != 0x0057 )
				{
				Weird("non_ip_packet_in_encap", ip_hdr, encapsulation);
				return;
				}

			proto = (ppp_proto == 0x0021) ? IPPROTO_IPV4 : IPPROTO_IPV6;
			}

		data += gre_len + ppp_len + eth_len + erspan_len;
		len -= gre_len + ppp_len + eth_len + erspan_len;
		caplen -= gre_len + ppp_len + eth_len + erspan_len;

		// Treat GRE tunnel like IP tunnels, fallthrough to logic below now
		// that GRE header is stripped and only payload packet remains.
		// The only thing different is the tunnel type enum value to use.
		tunnel_type = BifEnum::Tunnel::GRE;
		}

	case IPPROTO_IPV4:
	case IPPROTO_IPV6:
		{
		if ( ! BifConst::Tunnel::enable_ip )
			{
			Weird("IP_tunnel", ip_hdr, encapsulation);
			return;
			}

		if ( encapsulation &&
		     encapsulation->Depth() >= BifConst::Tunnel::max_depth )
			{
			Weird("exceeded_tunnel_max_depth", ip_hdr, encapsulation);
			return;
			}

		// Check for a valid inner packet first.
		IP_Hdr* inner = 0;
		int result = ParseIPPacket(caplen, data, proto, inner);
		if ( result == -2 )
			Weird("invalid_inner_IP_version", ip_hdr, encapsulation);
		else if ( result < 0 )
			Weird("truncated_inner_IP", ip_hdr, encapsulation);
		else if ( result > 0 )
			Weird("inner_IP_payload_length_mismatch", ip_hdr, encapsulation);

		if ( result != 0 )
			{
			delete inner;
			return;
			}

		// Look up to see if we've already seen this IP tunnel, identified
		// by the pair of IP addresses, so that we can always associate the
		// same UID with it.
		IPPair tunnel_idx;
		if ( ip_hdr->SrcAddr() < ip_hdr->DstAddr() )
			tunnel_idx = IPPair(ip_hdr->SrcAddr(), ip_hdr->DstAddr());
		else
			tunnel_idx = IPPair(ip_hdr->DstAddr(), ip_hdr->SrcAddr());

		IPTunnelMap::iterator it = ip_tunnels.find(tunnel_idx);

		if ( it == ip_tunnels.end() )
			{
			EncapsulatingConn ec(ip_hdr->SrcAddr(), ip_hdr->DstAddr(),
			                     tunnel_type);
			ip_tunnels[tunnel_idx] = TunnelActivity(ec, network_time);
			timer_mgr->Add(new IPTunnelTimer(network_time, tunnel_idx));
			}
		else
			it->second.second = network_time;

		DoNextInnerPacket(t, pkt, inner, encapsulation,
		                  ip_tunnels[tunnel_idx].first);

		return;
		}

	case IPPROTO_NONE:
		{
		// If the packet is encapsulated in Teredo, then it was a bubble and
		// the Teredo analyzer may have raised an event for that, else we're
		// not sure the reason for the No Next header in the packet.
		if ( ! ( encapsulation &&
		     encapsulation->LastType() == BifEnum::Tunnel::TEREDO ) )
			Weird("ipv6_no_next", pkt);

		return;
		}

	default:
		Weird("unknown_protocol", pkt, encapsulation, fmt("%d", proto));
		return;
	}

	ConnIDKey key = BuildConnIDKey(id);
	Connection* conn = nullptr;

	// FIXME: The following is getting pretty complex. Need to split up
	// into separate functions.
	auto it = d->find(key);
	if ( it != d->end() )
		conn = it->second;

	if ( ! conn )
		{
		conn = NewConn(key, t, &id, data, proto, ip_hdr->FlowLabel(), pkt, encapsulation);
		if ( conn )
			InsertConnection(d, key, conn);
		}
	else
		{
		// We already know that connection.
		if ( conn->IsReuse(t, data) )
			{
			conn->Event(connection_reused, 0);

			Remove(conn);
			conn = NewConn(key, t, &id, data, proto, ip_hdr->FlowLabel(), pkt, encapsulation);
			if ( conn )
				InsertConnection(d, key, conn);
			}
		else
			{
			conn->CheckEncapsulation(encapsulation);
			}
		}

	if ( ! conn )
		return;

	int record_packet = 1;	// whether to record the packet at all
	int record_content = 1;	// whether to record its data

	int is_orig = (id.src_addr == conn->OrigAddr()) &&
			(id.src_port == conn->OrigPort());

	conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

	Val* pkt_hdr_val = 0;

	if ( ipv6_ext_headers && ip_hdr->NumHeaders() > 1 )
		{
		pkt_hdr_val = ip_hdr->BuildPktHdrVal();
		conn->Event(ipv6_ext_headers, 0, pkt_hdr_val);
		}

	if ( new_packet )
		conn->Event(new_packet, 0,
		        pkt_hdr_val ? pkt_hdr_val->Ref() : ip_hdr->BuildPktHdrVal());

	conn->NextPacket(t, is_orig, ip_hdr, len, caplen, data,
				record_packet, record_content, pkt);

	if ( f )
		{
		// Above we already recorded the fragment in its entirety.
		f->DeleteTimer();
		}

	else if ( record_packet )
		{
		if ( record_content )
			dump_this_packet = 1;	// save the whole thing

		else
			{
			int hdr_len = data - pkt->data;
			DumpPacket(pkt, hdr_len);	// just save the header
			}
		}
	}

void NetSessions::DoNextInnerPacket(double t, const Packet* pkt,
		const IP_Hdr* inner, const EncapsulationStack* prev,
		const EncapsulatingConn& ec)
	{
	uint32_t caplen, len;
	caplen = len = inner->TotalLen();

	pkt_timeval ts;
	int link_type;
	Layer3Proto l3_proto;

	if ( pkt )
		ts = pkt->ts;
	else
		{
		ts.tv_sec = (time_t) network_time;
		ts.tv_usec = (suseconds_t)
		    ((network_time - (double)ts.tv_sec) * 1000000);
		}

	const u_char* data = 0;

	if ( inner->IP4_Hdr() )
		{
		data = (const u_char*) inner->IP4_Hdr();
		l3_proto = L3_IPV4;
		}
	else
		{
		data = (const u_char*) inner->IP6_Hdr();
		l3_proto = L3_IPV6;
		}

	EncapsulationStack* outer = prev ?
			new EncapsulationStack(*prev) : new EncapsulationStack();
	outer->Add(ec);

	// Construct fake packet for DoNextPacket
	Packet p;
	p.Init(DLT_RAW, &ts, caplen, len, data, false, "");

	DoNextPacket(t, &p, inner, outer);

	delete inner;
	delete outer;
	}

int NetSessions::ParseIPPacket(int caplen, const u_char* const pkt, int proto,
		IP_Hdr*& inner)
	{
	if ( proto == IPPROTO_IPV6 )
		{
		if ( caplen < (int)sizeof(struct ip6_hdr) )
			return -1;

		const struct ip6_hdr* ip6 = (const struct ip6_hdr*) pkt;
		inner = new IP_Hdr(ip6, false, caplen);
		if ( ( ip6->ip6_ctlun.ip6_un2_vfc & 0xF0 ) != 0x60 )
			return -2;
		}

	else if ( proto == IPPROTO_IPV4 )
		{
		if ( caplen < (int)sizeof(struct ip) )
			return -1;

		const struct ip* ip4 = (const struct ip*) pkt;
		inner = new IP_Hdr(ip4, false);
		if ( ip4->ip_v != 4 )
			return -2;
		}

	else
		{
		reporter->InternalWarning("Bad IP protocol version in ParseIPPacket");
		return -1;
		}

	if ( (uint32_t)caplen != inner->TotalLen() )
		return (uint32_t)caplen < inner->TotalLen() ? -1 : 1;

	return 0;
	}

bool NetSessions::CheckHeaderTrunc(int proto, uint32_t len, uint32_t caplen,
                                   const Packet* p, const EncapsulationStack* encap)
	{
	uint32_t min_hdr_len = 0;
	switch ( proto ) {
	case IPPROTO_TCP:
		min_hdr_len = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		min_hdr_len = sizeof(struct udphdr);
		break;
	case IPPROTO_IPV4:
		min_hdr_len = sizeof(struct ip);
		break;
	case IPPROTO_IPV6:
		min_hdr_len = sizeof(struct ip6_hdr);
		break;
	case IPPROTO_NONE:
		min_hdr_len = 0;
		break;
	case IPPROTO_GRE:
		min_hdr_len = 4;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	default:
		// Use for all other packets.
		min_hdr_len = ICMP_MINLEN;
		break;
	}

	if ( len < min_hdr_len )
		{
		Weird("truncated_header", p, encap);
		return true;
		}

	if ( caplen < min_hdr_len )
		{
		Weird("internally_truncated_header", p, encap);
		return true;
		}

	return false;
	}

FragReassembler* NetSessions::NextFragment(double t, const IP_Hdr* ip,
					const u_char* pkt)
	{
	uint32_t frag_id = ip->ID();

	FragReassemblerKey key = std::make_tuple(ip->SrcAddr(), ip->DstAddr(), frag_id);

	FragReassembler* f = nullptr;
	auto it = fragments.find(key);
	if ( it != fragments.end() )
		f = it->second;

	if ( ! f )
		{
		f = new FragReassembler(this, ip, pkt, key, t);
		fragments[key] = f;
		if ( fragments.size() > stats.max_fragments )
			stats.max_fragments = fragments.size();
		return f;
		}

	f->AddFragment(t, ip, pkt);
	return f;
	}

Connection* NetSessions::FindConnection(Val* v)
	{
	BroType* vt = v->Type();
	if ( ! IsRecord(vt->Tag()) )
		return 0;

	RecordType* vr = vt->AsRecordType();
	const val_list* vl = v->AsRecord();

	int orig_h, orig_p;	// indices into record's value list
	int resp_h, resp_p;

	if ( vr == conn_id )
		{
		orig_h = 0;
		orig_p = 1;
		resp_h = 2;
		resp_p = 3;
		}

	else
		{
		// While it's not a conn_id, it may have equivalent fields.
		orig_h = vr->FieldOffset("orig_h");
		resp_h = vr->FieldOffset("resp_h");
		orig_p = vr->FieldOffset("orig_p");
		resp_p = vr->FieldOffset("resp_p");

		if ( orig_h < 0 || resp_h < 0 || orig_p < 0 || resp_p < 0 )
			return 0;

		// ### we ought to check that the fields have the right
		// types, too.
		}

	const IPAddr& orig_addr = (*vl)[orig_h]->AsAddr();
	const IPAddr& resp_addr = (*vl)[resp_h]->AsAddr();

	PortVal* orig_portv = (*vl)[orig_p]->AsPortVal();
	PortVal* resp_portv = (*vl)[resp_p]->AsPortVal();

	ConnID id;

	id.src_addr = orig_addr;
	id.dst_addr = resp_addr;

	id.src_port = htons((unsigned short) orig_portv->Port());
	id.dst_port = htons((unsigned short) resp_portv->Port());

	id.is_one_way = 0;	// ### incorrect for ICMP connections

	ConnIDKey key = BuildConnIDKey(id);
	ConnectionMap* d;

	if ( orig_portv->IsTCP() )
		d = &tcp_conns;
	else if ( orig_portv->IsUDP() )
		d = &udp_conns;
	else if ( orig_portv->IsICMP() )
		d = &icmp_conns;
	else
		{
		// This can happen due to pseudo-connections we
		// construct, for example for packet headers embedded
		// in ICMPs.
		return 0;
		}

	Connection* conn = nullptr;
	auto it = d->find(key);
	if ( it != d->end() )
		conn = it->second;

	return conn;
	}

void NetSessions::Remove(Connection* c)
	{
	if ( c->IsKeyValid() )
		{
		const ConnIDKey& key = c->Key();
		c->CancelTimers();

		if ( c->ConnTransport() == TRANSPORT_TCP )
			{
			auto ta = static_cast<analyzer::tcp::TCP_Analyzer*>(c->GetRootAnalyzer());
			assert(ta->IsAnalyzer("TCP"));
			analyzer::tcp::TCP_Endpoint* to = ta->Orig();
			analyzer::tcp::TCP_Endpoint* tr = ta->Resp();

			tcp_stats.StateLeft(to->state, tr->state);
			}

		c->Done();
		c->RemovalEvent();

		// Zero out c's copy of the key, so that if c has been Ref()'d
		// up, we know on a future call to Remove() that it's no
		// longer in the dictionary.
		c->ClearKey();

		switch ( c->ConnTransport() ) {
		case TRANSPORT_TCP:
			if ( tcp_conns.erase(key) == 0 )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_UDP:
			if ( udp_conns.erase(key) == 0 )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_ICMP:
			if ( icmp_conns.erase(key) == 0 )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_UNKNOWN:
			reporter->InternalWarning("unknown transport when removing connection");
			break;
		}

		Unref(c);
		}
	}

void NetSessions::Remove(FragReassembler* f)
	{
	if ( ! f )
		return;

	if ( fragments.erase(f->Key()) == 0 )
		reporter->InternalWarning("fragment reassembler not in dict");

	Unref(f);
	}

void NetSessions::Insert(Connection* c)
	{
	assert(c->IsKeyValid());

	Connection* old = nullptr;

	switch ( c->ConnTransport() ) {
	// Remove first. Otherwise the map would still reference the old key for
	// already existing connections.

	case TRANSPORT_TCP:
		old = LookupConn(tcp_conns, c->Key());
		tcp_conns.erase(c->Key());
		InsertConnection(&tcp_conns, c->Key(), c);
		break;

	case TRANSPORT_UDP:
		old = LookupConn(udp_conns, c->Key());
		udp_conns.erase(c->Key());
		InsertConnection(&udp_conns, c->Key(), c);
		break;

	case TRANSPORT_ICMP:
		old = LookupConn(icmp_conns, c->Key());
		icmp_conns.erase(c->Key());
		InsertConnection(&icmp_conns, c->Key(), c);
		break;

	default:
		reporter->InternalWarning("unknown connection type");
		Unref(c);
		return;
	}

	if ( old && old != c )
		{
		// Some clean-ups similar to those in Remove() (but invisible
		// to the script layer).
		old->CancelTimers();
		old->ClearKey();
		Unref(old);
		}
	}

void NetSessions::Drain()
	{
	for ( const auto& entry : tcp_conns )
		{
		Connection* tc = entry.second;
		tc->Done();
		tc->RemovalEvent();
		}

	for ( const auto& entry : udp_conns )
		{
		Connection* uc = entry.second;
		uc->Done();
		uc->RemovalEvent();
		}

	for ( const auto& entry : icmp_conns )
		{
		Connection* ic = entry.second;
		ic->Done();
		ic->RemovalEvent();
		}
	}

void NetSessions::GetStats(SessionStats& s) const
	{
	s.num_TCP_conns = tcp_conns.size();
	s.cumulative_TCP_conns = stats.cumulative_TCP_conns;
	s.num_UDP_conns = udp_conns.size();
	s.cumulative_UDP_conns = stats.cumulative_UDP_conns;
	s.num_ICMP_conns = icmp_conns.size();
	s.cumulative_ICMP_conns = stats.cumulative_ICMP_conns;
	s.num_fragments = fragments.size();
	s.num_packets = num_packets_processed;

	s.max_TCP_conns = stats.max_TCP_conns;
	s.max_UDP_conns = stats.max_UDP_conns;
	s.max_ICMP_conns = stats.max_ICMP_conns;
	s.max_fragments = stats.max_fragments;
	}

Connection* NetSessions::NewConn(const ConnIDKey& k, double t, const ConnID* id,
					const u_char* data, int proto, uint32_t flow_label,
					const Packet* pkt, const EncapsulationStack* encapsulation)
	{
	// FIXME: This should be cleaned up a bit, it's too protocol-specific.
	// But I'm not yet sure what the right abstraction for these things is.
	int src_h = ntohs(id->src_port);
	int dst_h = ntohs(id->dst_port);
	int flags = 0;

	// Hmm... This is not great.
	TransportProto tproto = TRANSPORT_UNKNOWN;
	switch ( proto ) {
		case IPPROTO_ICMP:
			tproto = TRANSPORT_ICMP;
			break;
		case IPPROTO_TCP:
			tproto = TRANSPORT_TCP;
			break;
		case IPPROTO_UDP:
			tproto = TRANSPORT_UDP;
			break;
		case IPPROTO_ICMPV6:
			tproto = TRANSPORT_ICMP;
			break;
		default:
			reporter->InternalWarning("unknown transport protocol");
			return 0;
	};

	if ( tproto == TRANSPORT_TCP )
		{
		const struct tcphdr* tp = (const struct tcphdr*) data;
		flags = tp->th_flags;
		}

	bool flip = false;

	if ( ! WantConnection(src_h, dst_h, tproto, flags, flip) )
		return 0;

	Connection* conn = new Connection(this, k, t, id, flow_label, pkt, encapsulation);
	conn->SetTransport(tproto);

	if ( flip )
		conn->FlipRoles();

	if ( ! analyzer_mgr->BuildInitialAnalyzerTree(conn) )
		{
		conn->Done();
		Unref(conn);
		return 0;
		}

	if ( new_connection )
		conn->Event(new_connection, 0);

	return conn;
	}

Connection* NetSessions::LookupConn(const ConnectionMap& conns, const ConnIDKey& key)
	{
	auto it = conns.find(key);
	if ( it != conns.end() )
		return it->second;

	return nullptr;
	}

bool NetSessions::IsLikelyServerPort(uint32_t port, TransportProto proto) const
	{
	// We keep a cached in-core version of the table to speed up the lookup.
	static set<bro_uint_t> port_cache;
	static bool have_cache = false;

	if ( ! have_cache )
		{
		ListVal* lv = likely_server_ports->ConvertToPureList();
		for ( int i = 0; i < lv->Length(); i++ )
			port_cache.insert(lv->Index(i)->InternalUnsigned());
		have_cache = true;
		Unref(lv);
		}

	// We exploit our knowledge of PortVal's internal storage mechanism
	// here.
	if ( proto == TRANSPORT_TCP )
		port |= TCP_PORT_MASK;
	else if ( proto == TRANSPORT_UDP )
		port |= UDP_PORT_MASK;
	else if ( proto == TRANSPORT_ICMP )
		port |= ICMP_PORT_MASK;

	return port_cache.find(port) != port_cache.end();
	}

bool NetSessions::WantConnection(uint16_t src_port, uint16_t dst_port,
					TransportProto transport_proto,
					uint8_t tcp_flags, bool& flip_roles)
	{
	flip_roles = false;

	if ( transport_proto == TRANSPORT_TCP )
		{
		if ( ! (tcp_flags & TH_SYN) || (tcp_flags & TH_ACK) )
			{
			// The new connection is starting either without a SYN,
			// or with a SYN ack. This means it's a partial connection.
			if ( ! partial_connection_ok )
				return false;

			if ( tcp_flags & TH_SYN && ! tcp_SYN_ack_ok )
				return false;

			// Try to guess true responder by the port numbers.
			// (We might also think that for SYN acks we could
			// safely flip the roles, but that doesn't work
			// for stealth scans.)
			if ( IsLikelyServerPort(src_port, TRANSPORT_TCP) )
				{ // connection is a candidate for flipping
				if ( IsLikelyServerPort(dst_port, TRANSPORT_TCP) )
					// Hmmm, both source and destination
					// are plausible.  Heuristic: flip only
					// if (1) this isn't a SYN ACK (to avoid
					// confusing stealth scans) and
					// (2) dest port > src port (to favor
					// more plausible servers).
					flip_roles = ! (tcp_flags & TH_SYN) && src_port < dst_port;
				else
					// Source is plausible, destination isn't.
					flip_roles = true;
				}
			}
		}

	else if ( transport_proto == TRANSPORT_UDP )
		flip_roles =
			IsLikelyServerPort(src_port, TRANSPORT_UDP) &&
			! IsLikelyServerPort(dst_port, TRANSPORT_UDP);

	return true;
	}

void NetSessions::DumpPacket(const Packet *pkt, int len)
	{
	if ( ! pkt_dumper )
		return;

	if ( len != 0 )
		{
		if ( (uint32_t)len > pkt->cap_len )
			reporter->Warning("bad modified caplen");
		else
			const_cast<Packet *>(pkt)->cap_len = len;
		}

	pkt_dumper->Dump(pkt);
	}

void NetSessions::Weird(const char* name, const Packet* pkt,
                        const EncapsulationStack* encap, const char* addl)
	{
	if ( pkt )
		dump_this_packet = 1;

	if ( encap && encap->LastType() != BifEnum::Tunnel::NONE )
		reporter->Weird(fmt("%s_in_tunnel", name), addl);
	else
		reporter->Weird(name, addl);
	}

void NetSessions::Weird(const char* name, const IP_Hdr* ip,
                        const EncapsulationStack* encap, const char* addl)
	{
	if ( encap && encap->LastType() != BifEnum::Tunnel::NONE )
		reporter->Weird(ip->SrcAddr(), ip->DstAddr(),
		                fmt("%s_in_tunnel", name), addl);
	else
		reporter->Weird(ip->SrcAddr(), ip->DstAddr(), name, addl);
	}

unsigned int NetSessions::ConnectionMemoryUsage()
	{
	unsigned int mem = 0;

	if ( terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : tcp_conns )
		mem += entry.second->MemoryAllocation();

	for ( const auto& entry : udp_conns )
		mem += entry.second->MemoryAllocation();

	for ( const auto& entry : icmp_conns )
		mem += entry.second->MemoryAllocation();

	return mem;
	}

unsigned int NetSessions::ConnectionMemoryUsageConnVals()
	{
	unsigned int mem = 0;

	if ( terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : tcp_conns )
		mem += entry.second->MemoryAllocationConnVal();

	for ( const auto& entry : udp_conns )
		mem += entry.second->MemoryAllocationConnVal();

	for ( const auto& entry : icmp_conns )
		mem += entry.second->MemoryAllocationConnVal();

	return mem;
	}

unsigned int NetSessions::MemoryAllocation()
	{
	if ( terminating )
		// Connections have been flushed already.
		return 0;

	return ConnectionMemoryUsage()
		+ padded_sizeof(*this)
		+ (tcp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ (udp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ (icmp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ (fragments.size() * (sizeof(FragmentMap::key_type) + sizeof(FragmentMap::value_type)))
		// FIXME: MemoryAllocation() not implemented for rest.
		;
	}

void NetSessions::InsertConnection(ConnectionMap* m, const ConnIDKey& key, Connection* conn)
	{
	(*m)[key] = conn;

	switch ( conn->ConnTransport() )
		{
		case TRANSPORT_TCP:
			stats.cumulative_TCP_conns++;
			if ( m->size() > stats.max_TCP_conns )
				stats.max_TCP_conns = m->size();
			break;
		case TRANSPORT_UDP:
			stats.cumulative_UDP_conns++;
			if ( m->size() > stats.max_UDP_conns )
				stats.max_UDP_conns = m->size();
			break;
		case TRANSPORT_ICMP:
			stats.cumulative_ICMP_conns++;
			if ( m->size() > stats.max_ICMP_conns )
				stats.max_ICMP_conns = m->size();
			break;
		default: break;
		}
	}
