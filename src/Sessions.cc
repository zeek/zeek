// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "zeek/Sessions.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>

#include "zeek/Desc.h"
#include "zeek/RunState.h"
#include "zeek/Event.h"
#include "zeek/Timer.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/TunnelEncapsulation.h"

#include "zeek/analyzer/protocol/icmp/ICMP.h"
#include "zeek/analyzer/protocol/udp/UDP.h"
#include "zeek/analyzer/protocol/stepping-stone/SteppingStone.h"
#include "zeek/analyzer/Manager.h"

#include "zeek/iosource/IOSource.h"
#include "zeek/packet_analysis/Manager.h"

#include "analyzer/protocol/stepping-stone/events.bif.h"

// These represent NetBIOS services on ephemeral ports.  They're numbered
// so that we can use a single int to hold either an actual TCP/UDP server
// port or one of these.
enum NetBIOS_Service {
	NETBIOS_SERVICE_START = 0x10000L,	// larger than any port
	NETBIOS_SERVICE_DCE_RPC,
};

zeek::NetSessions* zeek::sessions;
zeek::NetSessions*& sessions = zeek::sessions;

namespace zeek {

NetSessions::NetSessions()
	{
	if ( stp_correlate_pair )
		stp_manager = new analyzer::stepping_stone::SteppingStoneManager();
	else
		stp_manager = nullptr;

	packet_filter = nullptr;

	memset(&stats, 0, sizeof(SessionStats));
	}

NetSessions::~NetSessions()
	{
	delete packet_filter;
	delete stp_manager;

	for ( const auto& entry : tcp_conns )
		Unref(entry.second);
	for ( const auto& entry : udp_conns )
		Unref(entry.second);
	for ( const auto& entry : icmp_conns )
		Unref(entry.second);

	detail::fragment_mgr->Clear();
	}

void NetSessions::Done()
	{
	}

void NetSessions::ProcessTransportLayer(double t, const Packet* pkt, size_t remaining)
	{
	const std::unique_ptr<IP_Hdr>& ip_hdr = pkt->ip_hdr;

	uint32_t len = ip_hdr->TotalLen();
	uint16_t ip_hdr_len = ip_hdr->HdrLen();

	if ( len < ip_hdr_len )
		{
		sessions->Weird("bogus_IP_header_lengths", pkt);
		return;
		}

	len -= ip_hdr_len;	// remove IP header

	int proto = ip_hdr->NextProto();

	if ( CheckHeaderTrunc(proto, len, remaining, pkt) )
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
		id.is_one_way = false;
		d = &tcp_conns;
		break;
		}

	case IPPROTO_UDP:
		{
		const struct udphdr* up = (const struct udphdr *) data;
		id.src_port = up->uh_sport;
		id.dst_port = up->uh_dport;
		id.is_one_way = false;
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

	default:
		Weird("unknown_protocol", pkt, util::fmt("%d", proto));
		return;
	}

	detail::ConnIDKey key = detail::BuildConnIDKey(id);
	Connection* conn = nullptr;

	// FIXME: The following is getting pretty complex. Need to split up
	// into separate functions.
	auto it = d->find(key);
	if ( it != d->end() )
		conn = it->second;

	if ( ! conn )
		{
		conn = NewConn(key, t, &id, data, proto, ip_hdr->FlowLabel(), pkt);
		if ( conn )
			InsertConnection(d, key, conn);
		}
	else
		{
		// We already know that connection.
		if ( conn->IsReuse(t, data) )
			{
			conn->Event(connection_reused, nullptr);

			Remove(conn);
			conn = NewConn(key, t, &id, data, proto, ip_hdr->FlowLabel(), pkt);
			if ( conn )
				InsertConnection(d, key, conn);
			}
		else
			{
			conn->CheckEncapsulation(pkt->encap);
			}
		}

	if ( ! conn )
		return;

	int record_packet = 1;	// whether to record the packet at all
	int record_content = 1;	// whether to record its data

	bool is_orig = (id.src_addr == conn->OrigAddr()) &&
			(id.src_port == conn->OrigPort());

	conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

	ValPtr pkt_hdr_val;

	if ( ipv6_ext_headers && ip_hdr->NumHeaders() > 1 )
		{
		pkt_hdr_val = ip_hdr->ToPktHdrVal();
		conn->EnqueueEvent(ipv6_ext_headers, nullptr, conn->ConnVal(),
		                   pkt_hdr_val);
		}

	if ( new_packet )
		conn->EnqueueEvent(new_packet, nullptr, conn->ConnVal(), pkt_hdr_val ?
		                   std::move(pkt_hdr_val) : ip_hdr->ToPktHdrVal());

	conn->NextPacket(t, is_orig, ip_hdr.get(), len, remaining, data,
	                 record_packet, record_content, pkt);

	// We skip this block for reassembled packets because the pointer
	// math wouldn't work.
	if ( ! ip_hdr->reassembled && record_packet )
		{
		if ( record_content )
			pkt->dump_packet = true;	// save the whole thing

		else
			{
			int hdr_len = data - pkt->data;
			packet_mgr->DumpPacket(pkt, hdr_len);	// just save the header
			}
		}
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
                                   const Packet* p)
	{
	uint32_t min_hdr_len = 0;
	switch ( proto ) {
	case IPPROTO_TCP:
		min_hdr_len = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		min_hdr_len = sizeof(struct udphdr);
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
		Weird("truncated_header", p);
		return true;
		}

	if ( caplen < min_hdr_len )
		{
		Weird("internally_truncated_header", p);
		return true;
		}

	return false;
	}

Connection* NetSessions::FindConnection(Val* v)
	{
	const auto& vt = v->GetType();
	if ( ! IsRecord(vt->Tag()) )
		return nullptr;

	RecordType* vr = vt->AsRecordType();
	auto vl = v->As<RecordVal*>();

	int orig_h, orig_p;	// indices into record's value list
	int resp_h, resp_p;

	if ( vr == id::conn_id )
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
			return nullptr;

		// ### we ought to check that the fields have the right
		// types, too.
		}

	const IPAddr& orig_addr = vl->GetFieldAs<AddrVal>(orig_h);
	const IPAddr& resp_addr = vl->GetFieldAs<AddrVal>(resp_h);

	const PortVal* orig_portv = vl->GetFieldAs<PortVal>(orig_p);
	const PortVal* resp_portv = vl->GetFieldAs<PortVal>(resp_p);

	ConnID id;

	id.src_addr = orig_addr;
	id.dst_addr = resp_addr;

	id.src_port = htons((unsigned short) orig_portv->Port());
	id.dst_port = htons((unsigned short) resp_portv->Port());

	id.is_one_way = false;	// ### incorrect for ICMP connections

	detail::ConnIDKey key = detail::BuildConnIDKey(id);
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
		return nullptr;
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
		const detail::ConnIDKey& key = c->Key();
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

void NetSessions::Clear()
	{
	for ( const auto& entry : tcp_conns )
		Unref(entry.second);
	for ( const auto& entry : udp_conns )
		Unref(entry.second);
	for ( const auto& entry : icmp_conns )
		Unref(entry.second);

	tcp_conns.clear();
	udp_conns.clear();
	icmp_conns.clear();

	detail::fragment_mgr->Clear();
	}

void NetSessions::GetStats(SessionStats& s) const
	{
	s.num_TCP_conns = tcp_conns.size();
	s.cumulative_TCP_conns = stats.cumulative_TCP_conns;
	s.num_UDP_conns = udp_conns.size();
	s.cumulative_UDP_conns = stats.cumulative_UDP_conns;
	s.num_ICMP_conns = icmp_conns.size();
	s.cumulative_ICMP_conns = stats.cumulative_ICMP_conns;
	s.num_fragments = detail::fragment_mgr->Size();
	s.num_packets = packet_mgr->PacketsProcessed();

	s.max_TCP_conns = stats.max_TCP_conns;
	s.max_UDP_conns = stats.max_UDP_conns;
	s.max_ICMP_conns = stats.max_ICMP_conns;
	s.max_fragments = detail::fragment_mgr->MaxFragments();
	}

Connection* NetSessions::NewConn(const detail::ConnIDKey& k, double t, const ConnID* id,
                                 const u_char* data, int proto, uint32_t flow_label,
                                 const Packet* pkt)
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
			return nullptr;
	};

	if ( tproto == TRANSPORT_TCP )
		{
		const struct tcphdr* tp = (const struct tcphdr*) data;
		flags = tp->th_flags;
		}

	bool flip = false;

	if ( ! WantConnection(src_h, dst_h, tproto, flags, flip) )
		return nullptr;

	Connection* conn = new Connection(this, k, t, id, flow_label, pkt);
	conn->SetTransport(tproto);

	if ( flip )
		conn->FlipRoles();

	if ( ! analyzer_mgr->BuildInitialAnalyzerTree(conn) )
		{
		conn->Done();
		Unref(conn);
		return nullptr;
		}

	if ( new_connection )
		conn->Event(new_connection, nullptr);

	return conn;
	}

Connection* NetSessions::LookupConn(const ConnectionMap& conns, const detail::ConnIDKey& key)
	{
	auto it = conns.find(key);
	if ( it != conns.end() )
		return it->second;

	return nullptr;
	}

bool NetSessions::IsLikelyServerPort(uint32_t port, TransportProto proto) const
	{
	// We keep a cached in-core version of the table to speed up the lookup.
	static std::set<bro_uint_t> port_cache;
	static bool have_cache = false;

	if ( ! have_cache )
		{
		auto likely_server_ports = id::find_val<TableVal>("likely_server_ports");
		auto lv = likely_server_ports->ToPureListVal();
		for ( int i = 0; i < lv->Length(); i++ )
			port_cache.insert(lv->Idx(i)->InternalUnsigned());
		have_cache = true;
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
			if ( ! zeek::detail::partial_connection_ok )
				return false;

			if ( tcp_flags & TH_SYN && ! zeek::detail::tcp_SYN_ack_ok )
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

void NetSessions::Weird(const char* name, const Packet* pkt, const char* addl, const char* source)
	{
	const char* weird_name = name;

	if ( pkt )
		{
		pkt->dump_packet = true;

		if ( pkt->encap && pkt->encap->LastType() != BifEnum::Tunnel::NONE )
			weird_name = util::fmt("%s_in_tunnel", name);

		if ( pkt->ip_hdr )
			{
			reporter->Weird(pkt->ip_hdr->SrcAddr(), pkt->ip_hdr->DstAddr(), weird_name, addl, source);
			return;
			}
		}

	reporter->Weird(weird_name, addl, source);
	}

void NetSessions::Weird(const char* name, const IP_Hdr* ip, const char* addl)
	{
	reporter->Weird(ip->SrcAddr(), ip->DstAddr(), name, addl);
	}

unsigned int NetSessions::ConnectionMemoryUsage()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
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

	if ( run_state::terminating )
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
	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	return ConnectionMemoryUsage()
		+ padded_sizeof(*this)
		+ (tcp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ (udp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ (icmp_conns.size() * (sizeof(ConnectionMap::key_type) + sizeof(ConnectionMap::value_type)))
		+ detail::fragment_mgr->MemoryAllocation();
		// FIXME: MemoryAllocation() not implemented for rest.
		;
	}

void NetSessions::InsertConnection(ConnectionMap* m, const detail::ConnIDKey& key, Connection* conn)
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

} // namespace zeek
