// See the file "COPYING" in the main distribution directory for copyright.


#include "bro-config.h"

#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>

#include "Net.h"
#include "Event.h"
#include "Timer.h"
#include "NetVar.h"
#include "Sessions.h"
#include "Reporter.h"
#include "OSFinger.h"

#include "analyzer/protocol/icmp/ICMP.h"
#include "analyzer/protocol/udp/UDP.h"

#include "analyzer/protocol/stepping-stone/SteppingStone.h"
#include "analyzer/protocol/stepping-stone/events.bif.h"
#include "analyzer/protocol/backdoor/BackDoor.h"
#include "analyzer/protocol/backdoor/events.bif.h"
#include "analyzer/protocol/interconn/InterConn.h"
#include "analyzer/protocol/interconn/events.bif.h"
#include "analyzer/protocol/arp/ARP.h"
#include "analyzer/protocol/arp/events.bif.h"
#include "Discard.h"
#include "RuleMatcher.h"

#include "TunnelEncapsulation.h"

#include "analyzer/Manager.h"

// These represent NetBIOS services on ephemeral ports.  They're numbered
// so that we can use a single int to hold either an actual TCP/UDP server
// port or one of these.
enum NetBIOS_Service {
	NETBIOS_SERVICE_START = 0x10000L,	// larger than any port
	NETBIOS_SERVICE_DCE_RPC,
};

NetSessions* sessions;

void TimerMgrExpireTimer::Dispatch(double t, int is_expire)
	{
	if ( mgr->LastAdvance() + timer_mgr_inactivity_timeout < timer_mgr->Time() )
		{
		// Expired.
		DBG_LOG(DBG_TM, "TimeMgr %p has timed out", mgr);
		mgr->Expire();

		// Make sure events are executed.  They depend on the TimerMgr.
		::mgr.Drain();

		sessions->timer_mgrs.erase(mgr->GetTag());
		delete mgr;
		}
	else
		{
		// Reinstall timer.
		if ( ! is_expire )
			{
			double n = mgr->LastAdvance() +
					timer_mgr_inactivity_timeout;
			timer_mgr->Add(new TimerMgrExpireTimer(n, mgr));
			}
		}
	}

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
	TypeList* t = new TypeList();
	t->Append(base_type(TYPE_ADDR));	// source IP address
	t->Append(base_type(TYPE_ADDR));	// dest IP address
	t->Append(base_type(TYPE_COUNT));	// source and dest ports

	ch = new CompositeHash(t);

	Unref(t);

	tcp_conns.SetDeleteFunc(bro_obj_delete_func);
	udp_conns.SetDeleteFunc(bro_obj_delete_func);
	icmp_conns.SetDeleteFunc(bro_obj_delete_func);
	fragments.SetDeleteFunc(bro_obj_delete_func);

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

	build_backdoor_analyzer =
		backdoor_stats || rlogin_signature_found ||
		telnet_signature_found || ssh_signature_found ||
		root_backdoor_signature_found || ftp_signature_found ||
		napster_signature_found || kazaa_signature_found ||
		http_signature_found || http_proxy_signature_found;

	dump_this_packet = 0;
	num_packets_processed = 0;

	if ( OS_version_found )
		{
		SYN_OS_Fingerprinter = new OSFingerprint(SYN_FINGERPRINT_MODE);
		if ( SYN_OS_Fingerprinter->Error() )
			exit(1);
		}
	else
		SYN_OS_Fingerprinter = 0;

	if ( pkt_profile_mode && pkt_profile_freq > 0 && pkt_profile_file )
		pkt_profiler = new PacketProfiler(pkt_profile_mode,
				pkt_profile_freq, pkt_profile_file->AsFile());
	else
		pkt_profiler = 0;

	if ( arp_request || arp_reply || bad_arp )
		arp_analyzer = new analyzer::arp::ARP_Analyzer();
	else
		arp_analyzer = 0;
	}

NetSessions::~NetSessions()
	{
	delete ch;
	delete packet_filter;
	delete SYN_OS_Fingerprinter;
	delete pkt_profiler;
	Unref(arp_analyzer);
	delete discarder;
	delete stp_manager;
	}

void NetSessions::Done()
	{
	}

void NetSessions::NextPacket(double t, const Packet* pkt)
	{
	SegmentProfiler(segment_logger, "dispatching-packet");

	if ( raw_packet )
		{
		val_list* vl = new val_list();
		vl->append(pkt->BuildPktHdrVal());
		mgr.QueueEvent(raw_packet, vl);
		}

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

	uint32 caplen = pkt->cap_len - pkt->hdr_size;

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

int NetSessions::CheckConnectionTag(Connection* conn)
	{
	if ( current_iosrc->GetCurrentTag() )
		{
		// Packet is tagged.
		if ( conn->GetTimerMgr() == timer_mgr )
			{
			// Connection uses global timer queue.  But the
			// packet has a tag that means we got it externally,
			// probably from the Time Machine.
			DBG_LOG(DBG_TM, "got packet with tag %s for already"
					"known connection, reinstantiating",
					current_iosrc->GetCurrentTag()->c_str());
			return 0;
			}
		else
			{
			// Connection uses local timer queue.
			TimerMgrMap::iterator i =
				timer_mgrs.find(*current_iosrc->GetCurrentTag());
			if ( i != timer_mgrs.end() &&
			     conn->GetTimerMgr() != i->second )
				{
				// Connection uses different local queue
				// than the tag for the current packet
				// indicates.
				//
				// This can happen due to:
				//     (1) getting same packets with
				//		different tags
				//     (2) timer mgr having already expired
				DBG_LOG(DBG_TM, "packet ignored due old/inconsistent tag");
				return -1;
				}

			return 1;
			}
		}

	// Packet is not tagged.
	if ( conn->GetTimerMgr() != timer_mgr )
		{
		// Connection does not use the global timer queue.  That
		// means that this is a live packet belonging to a
		// connection for which we have already switched to
		// processing external input.
		DBG_LOG(DBG_TM, "packet ignored due to processing it in external data");
		return -1;
		}

	return 1;
	}

static unsigned int gre_header_len(uint16 flags)
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
	uint32 caplen = pkt->cap_len - pkt->hdr_size;
	const struct ip* ip4 = ip_hdr->IP4_Hdr();

	uint32 len = ip_hdr->TotalLen();
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
	uint16 ip_hdr_len = ip_hdr->HdrLen();
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
			{
			val_list* vl = new val_list();
			vl->append(ip_hdr->BuildPktHdrVal());
			mgr.QueueEvent(esp_packet, vl);
			}

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
			{
			val_list* vl = new val_list();
			vl->append(ip_hdr->BuildPktHdrVal());
			mgr.QueueEvent(mobile_ipv6_message, vl);
			}

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
	Dictionary* d = 0;
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

		uint16 flags_ver = ntohs(*((uint16*)(data + 0)));
		uint16 proto_typ = ntohs(*((uint16*)(data + 2)));
		int gre_version = flags_ver & 0x0007;

		// If a carried packet has ethernet, this will help skip it.
		unsigned int eth_len = 0;
		unsigned int gre_len = gre_header_len(flags_ver);
		unsigned int ppp_len = gre_version == 1 ? 1 : 0;

		if ( gre_version != 0 && gre_version != 1 )
			{
			Weird(fmt("unknown_gre_version_%d", gre_version), ip_hdr,
			      encapsulation);
			return;
			}

		if ( gre_version == 0 )
			{
			if ( proto_typ == 0x6558 && len > gre_len + 14 )
				{
				// transparent ethernet bridging
				eth_len = 14;
				proto_typ = ntohs(*((uint16*)(data + gre_len + 12)));
				}

			if ( proto_typ == 0x0800 )
				proto = IPPROTO_IPV4;
			else if ( proto_typ == 0x86dd )
				proto = IPPROTO_IPV6;
			else
				{
				// Not IPv4/IPv6 payload.
				Weird(fmt("unknown_gre_protocol_%" PRIu16, proto_typ), ip_hdr,
				      encapsulation);
				return;
				}

			}

		else // gre_version == 1
			{
			if ( proto_typ != 0x880b )
				{
				// Enhanced GRE payload must be PPP.
				Weird("egre_protocol_type", ip_hdr, encapsulation);
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

		if ( len < gre_len + ppp_len + eth_len || caplen < gre_len + ppp_len + eth_len )
			{
			Weird("truncated_GRE", ip_hdr, encapsulation);
			return;
			}

		if ( gre_version == 1 )
			{
			int ppp_proto = *((uint8*)(data + gre_len));

			if ( ppp_proto != 0x0021 && ppp_proto != 0x0057 )
				{
				Weird("non_ip_packet_in_encap", ip_hdr, encapsulation);
				return;
				}

			proto = (ppp_proto == 0x0021) ? IPPROTO_IPV4 : IPPROTO_IPV6;
			}

		data += gre_len + ppp_len + eth_len;
		len -= gre_len + ppp_len + eth_len;
		caplen -= gre_len + ppp_len + eth_len;

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
		Weird(fmt("unknown_protocol_%d", proto), pkt, encapsulation);
		return;
	}

	HashKey* h = BuildConnIDHashKey(id);
	if ( ! h )
		reporter->InternalError("hash computation failed");

	Connection* conn = 0;

	// FIXME: The following is getting pretty complex. Need to split up
	// into separate functions.
	conn = (Connection*) d->Lookup(h);
	if ( ! conn )
		{
		conn = NewConn(h, t, &id, data, proto, ip_hdr->FlowLabel(), pkt, encapsulation);
		if ( conn )
			d->Insert(h, conn);
		}
	else
		{
		// We already know that connection.
		int consistent = CheckConnectionTag(conn);
		if ( consistent < 0 )
			{
			delete h;
			return;
			}

		if ( ! consistent || conn->IsReuse(t, data) )
			{
			if ( consistent )
				conn->Event(connection_reused, 0);

			Remove(conn);
			conn = NewConn(h, t, &id, data, proto, ip_hdr->FlowLabel(), pkt, encapsulation);
			if ( conn )
				d->Insert(h, conn);
			}
		else
			{
			delete h;
			conn->CheckEncapsulation(encapsulation);
			}
		}

	if ( ! conn )
		{
		delete h;
		return;
		}

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
	uint32 caplen, len;
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

	if ( (uint32)caplen != inner->TotalLen() )
		return (uint32)caplen < inner->TotalLen() ? -1 : 1;

	return 0;
	}

bool NetSessions::CheckHeaderTrunc(int proto, uint32 len, uint32 caplen,
                                   const Packet* p, const EncapsulationStack* encap)
	{
	uint32 min_hdr_len = 0;
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
	uint32 frag_id = ip->ID();

	ListVal* key = new ListVal(TYPE_ANY);
	key->Append(new AddrVal(ip->SrcAddr()));
	key->Append(new AddrVal(ip->DstAddr()));
	key->Append(new Val(frag_id, TYPE_COUNT));

	HashKey* h = ch->ComputeHash(key, 1);
	if ( ! h )
		reporter->InternalError("hash computation failed");

	FragReassembler* f = fragments.Lookup(h);
	if ( ! f )
		{
		f = new FragReassembler(this, ip, pkt, h, t);
		fragments.Insert(h, f);
		Unref(key);
		return f;
		}

	delete h;
	Unref(key);

	f->AddFragment(t, ip, pkt);
	return f;
	}

int NetSessions::Get_OS_From_SYN(struct os_type* retval,
		  uint16 tot, uint8 DF_flag, uint8 TTL, uint16 WSS,
		  uint8 ocnt, uint8* op, uint16 MSS, uint8 win_scale,
		  uint32 tstamp, /* uint8 TOS, */ uint32 quirks,
		  uint8 ECN) const
	{
	return SYN_OS_Fingerprinter ?
		SYN_OS_Fingerprinter->FindMatch(retval, tot, DF_flag, TTL,
				WSS, ocnt, op, MSS, win_scale, tstamp,
				quirks, ECN) : 0;
	}

bool NetSessions::CompareWithPreviousOSMatch(const IPAddr& addr, int id) const
	{
	return SYN_OS_Fingerprinter ?
		SYN_OS_Fingerprinter->CacheMatch(addr, id) : 0;
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

	HashKey* h = BuildConnIDHashKey(id);
	if ( ! h )
		reporter->InternalError("hash computation failed");

	Dictionary* d;

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
		delete h;
		return 0;
		}

	Connection* conn = (Connection*) d->Lookup(h);

	delete h;

	return conn;
	}

void NetSessions::Remove(Connection* c)
	{
	HashKey* k = c->Key();
	if ( k )
		{
		c->CancelTimers();

		analyzer::tcp::TCP_Analyzer* ta = (analyzer::tcp::TCP_Analyzer*) c->GetRootAnalyzer();
		if ( ta && c->ConnTransport() == TRANSPORT_TCP )
			{
			assert(ta->IsAnalyzer("TCP"));
			analyzer::tcp::TCP_Endpoint* to = ta->Orig();
			analyzer::tcp::TCP_Endpoint* tr = ta->Resp();

			tcp_stats.StateLeft(to->state, tr->state);
			}

		if ( c->IsPersistent() )
			persistence_serializer->Unregister(c);

		c->Done();

		if ( connection_state_remove )
			c->Event(connection_state_remove, 0);

		// Zero out c's copy of the key, so that if c has been Ref()'d
		// up, we know on a future call to Remove() that it's no
		// longer in the dictionary.
		c->ClearKey();

		switch ( c->ConnTransport() ) {
		case TRANSPORT_TCP:
			if ( ! tcp_conns.RemoveEntry(k) )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_UDP:
			if ( ! udp_conns.RemoveEntry(k) )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_ICMP:
			if ( ! icmp_conns.RemoveEntry(k) )
				reporter->InternalWarning("connection missing");
			break;

		case TRANSPORT_UNKNOWN:
			reporter->InternalWarning("unknown transport when removing connection");
			break;
		}

		Unref(c);
		delete k;
		}
	}

void NetSessions::Remove(FragReassembler* f)
	{
	if ( ! f )
		return;

	HashKey* k = f->Key();

	if ( k )
		{
		if ( ! fragments.RemoveEntry(k) )
			reporter->InternalWarning("fragment reassembler not in dict");
		}
	else
		reporter->InternalWarning("missing fragment reassembler hash key");

	Unref(f);
	}

void NetSessions::Insert(Connection* c)
	{
	assert(c->Key());

	Connection* old = 0;

	switch ( c->ConnTransport() ) {
	// Remove first. Otherwise the dictioanry would still
	// reference the old key for already existing connections.

	case TRANSPORT_TCP:
		old = (Connection*) tcp_conns.Remove(c->Key());
		tcp_conns.Insert(c->Key(), c);
		break;

	case TRANSPORT_UDP:
		old = (Connection*) udp_conns.Remove(c->Key());
		udp_conns.Insert(c->Key(), c);
		break;

	case TRANSPORT_ICMP:
		old = (Connection*) icmp_conns.Remove(c->Key());
		icmp_conns.Insert(c->Key(), c);
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
		if ( old->IsPersistent() )
			persistence_serializer->Unregister(old);
		delete old->Key();
		old->ClearKey();
		Unref(old);
		}
	}

void NetSessions::Drain()
	{
	IterCookie* cookie = tcp_conns.InitForIteration();
	Connection* tc;

	while ( (tc = tcp_conns.NextEntry(cookie)) )
		{
		tc->Done();
		tc->Event(connection_state_remove, 0);
		}

	cookie = udp_conns.InitForIteration();
	Connection* uc;

	while ( (uc = udp_conns.NextEntry(cookie)) )
		{
		uc->Done();
		uc->Event(connection_state_remove, 0);
		}

	cookie = icmp_conns.InitForIteration();
	Connection* ic;

	while ( (ic = icmp_conns.NextEntry(cookie)) )
		{
		ic->Done();
		ic->Event(connection_state_remove, 0);
		}

	ExpireTimerMgrs();
	}

void NetSessions::GetStats(SessionStats& s) const
	{
	s.num_TCP_conns = tcp_conns.Length();
	s.cumulative_TCP_conns = tcp_conns.NumCumulativeInserts();
	s.num_UDP_conns = udp_conns.Length();
	s.cumulative_UDP_conns = udp_conns.NumCumulativeInserts();
	s.num_ICMP_conns = icmp_conns.Length();
	s.cumulative_ICMP_conns = icmp_conns.NumCumulativeInserts();
	s.num_fragments = fragments.Length();
	s.num_packets = num_packets_processed;

	s.max_TCP_conns = tcp_conns.MaxLength();
	s.max_UDP_conns = udp_conns.MaxLength();
	s.max_ICMP_conns = icmp_conns.MaxLength();
	s.max_fragments = fragments.MaxLength();
	}

Connection* NetSessions::NewConn(HashKey* k, double t, const ConnID* id,
					const u_char* data, int proto, uint32 flow_label,
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

	bool external = conn->IsExternal();

	if ( external )
		conn->AppendAddl(fmt("tag=%s",
					conn->GetTimerMgr()->GetTag().c_str()));

	if ( new_connection )
		{
		conn->Event(new_connection, 0);

		if ( external )
			{
			val_list* vl = new val_list(2);
			vl->append(conn->BuildConnVal());
			vl->append(new StringVal(conn->GetTimerMgr()->GetTag().c_str()));
			conn->ConnectionEvent(connection_external, 0, vl);
			}
		}

	return conn;
	}

bool NetSessions::IsLikelyServerPort(uint32 port, TransportProto proto) const
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

bool NetSessions::WantConnection(uint16 src_port, uint16 dst_port,
					TransportProto transport_proto,
					uint8 tcp_flags, bool& flip_roles)
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

TimerMgr* NetSessions::LookupTimerMgr(const TimerMgr::Tag* tag, bool create)
	{
	if ( ! tag )
		{
		DBG_LOG(DBG_TM, "no tag, using global timer mgr %p", timer_mgr);
		return timer_mgr;
		}

	TimerMgrMap::iterator i = timer_mgrs.find(*tag);
	if ( i != timer_mgrs.end() )
		{
		DBG_LOG(DBG_TM, "tag %s, using non-global timer mgr %p", tag->c_str(), i->second);
		return i->second;
		}
	else
		{
		if ( ! create )
			return 0;

		// Create new queue for tag.
		TimerMgr* mgr = new CQ_TimerMgr(*tag);
		DBG_LOG(DBG_TM, "tag %s, creating new non-global timer mgr %p", tag->c_str(), mgr);
		timer_mgrs.insert(TimerMgrMap::value_type(*tag, mgr));
		double t = timer_mgr->Time() + timer_mgr_inactivity_timeout;
		timer_mgr->Add(new TimerMgrExpireTimer(t, mgr));
		return mgr;
		}
	}

void NetSessions::ExpireTimerMgrs()
	{
	for ( TimerMgrMap::iterator i = timer_mgrs.begin();
	      i != timer_mgrs.end(); ++i )
		{
		i->second->Expire();
		delete i->second;
		}
	}

void NetSessions::DumpPacket(const Packet *pkt, int len)
	{
	if ( ! pkt_dumper )
		return;

	if ( len != 0 )
		{
		if ( (uint32)len > pkt->cap_len )
			reporter->Warning("bad modified caplen");
		else
			const_cast<Packet *>(pkt)->cap_len = len;
		}

	pkt_dumper->Dump(pkt);
	}

void NetSessions::Weird(const char* name, const Packet* pkt,
                        const EncapsulationStack* encap)
	{
	if ( pkt )
		dump_this_packet = 1;

	if ( encap && encap->LastType() != BifEnum::Tunnel::NONE )
		reporter->Weird(fmt("%s_in_tunnel", name));
	else
		reporter->Weird(name);
	}

void NetSessions::Weird(const char* name, const IP_Hdr* ip,
                        const EncapsulationStack* encap)
	{
	if ( encap && encap->LastType() != BifEnum::Tunnel::NONE )
		reporter->Weird(ip->SrcAddr(), ip->DstAddr(),
		                fmt("%s_in_tunnel", name));
	else
		reporter->Weird(ip->SrcAddr(), ip->DstAddr(), name);
	}

unsigned int NetSessions::ConnectionMemoryUsage()
	{
	unsigned int mem = 0;

	if ( terminating )
		// Connections have been flushed already.
		return 0;

	IterCookie* cookie = tcp_conns.InitForIteration();
	Connection* tc;

	while ( (tc = tcp_conns.NextEntry(cookie)) )
		mem += tc->MemoryAllocation();

	cookie = udp_conns.InitForIteration();
	Connection* uc;

	while ( (uc = udp_conns.NextEntry(cookie)) )
		mem += uc->MemoryAllocation();

	cookie = icmp_conns.InitForIteration();
	Connection* ic;

	while ( (ic = icmp_conns.NextEntry(cookie)) )
		mem += ic->MemoryAllocation();

	return mem;
	}

unsigned int NetSessions::ConnectionMemoryUsageConnVals()
	{
	unsigned int mem = 0;

	if ( terminating )
		// Connections have been flushed already.
		return 0;

	IterCookie* cookie = tcp_conns.InitForIteration();
	Connection* tc;

	while ( (tc = tcp_conns.NextEntry(cookie)) )
		mem += tc->MemoryAllocationConnVal();

	cookie = udp_conns.InitForIteration();
	Connection* uc;

	while ( (uc = udp_conns.NextEntry(cookie)) )
		mem += uc->MemoryAllocationConnVal();

	cookie = icmp_conns.InitForIteration();
	Connection* ic;

	while ( (ic = icmp_conns.NextEntry(cookie)) )
		mem += ic->MemoryAllocationConnVal();

	return mem;
	}

unsigned int NetSessions::MemoryAllocation()
	{
	if ( terminating )
		// Connections have been flushed already.
		return 0;

	return ConnectionMemoryUsage()
		+ padded_sizeof(*this)
		+ ch->MemoryAllocation()
		// must take care we don't count the HaskKeys twice.
		+ tcp_conns.MemoryAllocation() - padded_sizeof(tcp_conns) -
		// 12 is sizeof(Key) from ConnID::BuildConnKey();
		// it can't be (easily) accessed here. :-(
			(tcp_conns.Length() * pad_size(12))
		+ udp_conns.MemoryAllocation() - padded_sizeof(udp_conns) -
			(udp_conns.Length() * pad_size(12))
		+ icmp_conns.MemoryAllocation() - padded_sizeof(icmp_conns) -
			(icmp_conns.Length() * pad_size(12))
		+ fragments.MemoryAllocation() - padded_sizeof(fragments)
		// FIXME: MemoryAllocation() not implemented for rest.
		;
	}
