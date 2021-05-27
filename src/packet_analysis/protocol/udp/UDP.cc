// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/udp/UDP.h"
#include "zeek/RunState.h"
#include "zeek/Conn.h"
#include "zeek/session/Manager.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"
#include "zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h"

#include "zeek/packet_analysis/protocol/udp/events.bif.h"

using namespace zeek::packet_analysis::UDP;
using namespace zeek::packet_analysis::IP;

constexpr uint32_t HIST_ORIG_DATA_PKT = 0x1;
constexpr uint32_t HIST_RESP_DATA_PKT = 0x2;
constexpr uint32_t HIST_ORIG_CORRUPT_PKT = 0x4;
constexpr uint32_t HIST_RESP_CORRUPT_PKT = 0x8;

UDPAnalyzer::UDPAnalyzer() : IPBasedAnalyzer("UDP", TRANSPORT_UDP, UDP_PORT_MASK, false)
	{
	}

SessionAdapter* UDPAnalyzer::MakeSessionAdapter(Connection* conn)
	{
	auto* root = new UDPSessionAdapter(conn);
	root->SetParent(this);

	conn->EnableStatusUpdateTimer();
	conn->SetInactivityTimeout(zeek::detail::udp_inactivity_timeout);

	return root;
	}

zeek::analyzer::pia::PIA* UDPAnalyzer::MakePIA(Connection* conn)
	{
	return new analyzer::pia::PIA_UDP(conn);
	}

void UDPAnalyzer::Initialize()
	{
	IPBasedAnalyzer::Initialize();

	const auto& id = detail::global_scope()->Find("Tunnel::vxlan_ports");

	if ( ! (id && id->GetVal()) )
		reporter->FatalError("Tunnel::vxlan_ports not defined");

	auto table_val = id->GetVal()->AsTableVal();
	auto port_list = table_val->ToPureListVal();

	for ( auto i = 0; i < port_list->Length(); ++i )
		vxlan_ports.emplace_back(port_list->Idx(i)->AsPortVal()->Port());
	}

bool UDPAnalyzer::WantConnection(uint16_t src_port, uint16_t dst_port,
                                 const u_char* data, bool& flip_roles) const
	{
	flip_roles = IsLikelyServerPort(src_port) && ! IsLikelyServerPort(dst_port);
	return true;
	}

bool UDPAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet,
                                 ConnTuple& tuple)
	{
	uint32_t min_hdr_len = sizeof(struct udphdr);
	if ( ! CheckHeaderTrunc(min_hdr_len, len, packet) )
		return false;

	tuple.src_addr = packet->ip_hdr->SrcAddr();
	tuple.dst_addr = packet->ip_hdr->DstAddr();

	const struct udphdr* up = (const struct udphdr *) packet->ip_hdr->Payload();
	tuple.src_port = up->uh_sport;
	tuple.dst_port = up->uh_dport;
	tuple.is_one_way = false;
	tuple.proto = TRANSPORT_UDP;

	return true;
	}

void UDPAnalyzer::DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt)
	{
	auto* adapter = static_cast<UDPSessionAdapter*>(c->GetSessionAdapter());

	const u_char* data = pkt->ip_hdr->Payload();
	int len = pkt->ip_hdr->PayloadLen();

	const struct udphdr* up = (const struct udphdr*) data;
	const std::unique_ptr<IP_Hdr>& ip = pkt->ip_hdr;

	adapter->DeliverPacket(len, data, is_orig, -1, ip.get(), remaining);

	// Increment data before checksum check so that data will
	// point to UDP payload even if checksum fails. Particularly,
	// it allows event packet_contents to get to the data.
	data += sizeof(struct udphdr);

	// We need the min() here because Ethernet frame padding can lead to
	// remaining > len.
	if ( packet_contents )
		adapter->PacketContents(data, std::min(len, remaining) - sizeof(struct udphdr));

	int chksum = up->uh_sum;

	auto validate_checksum =
		! run_state::current_pkt->l3_checksummed &&
		! zeek::detail::ignore_checksums &&
		! zeek::id::find_val<TableVal>("ignore_checksums_nets")->Contains(ip->IPHeaderSrcAddr()) &&
		remaining >=len;

	constexpr auto vxlan_len = 8;
	constexpr auto eth_len = 14;

	if ( validate_checksum &&
	     len > ((int)sizeof(struct udphdr) + vxlan_len + eth_len) &&
	     (data[0] & 0x08) == 0x08 )
		{
		if ( std::find(vxlan_ports.begin(), vxlan_ports.end(),
		               ntohs(up->uh_dport)) != vxlan_ports.end() )
			{
			// Looks like VXLAN on a well-known port, so the checksum should be
			// transmitted as zero, and we should accept that.  If not
			// transmitted as zero, then validating the checksum is optional.
			if ( chksum == 0 )
				validate_checksum = false;
			else
				validate_checksum = BifConst::Tunnel::validate_vxlan_checksums;
			}
		}

	if ( validate_checksum )
		{
		bool bad = false;

		if ( ip->IP4_Hdr() )
			{
			if ( chksum && ! ValidateChecksum(ip.get(), up, len) )
				bad = true;
			}

		/* checksum is not optional for IPv6 */
		else if ( ! ValidateChecksum(ip.get(), up, len) )
			bad = true;

		if ( bad )
			{
			adapter->HandleBadChecksum(is_orig);
			return;
			}
		}

	int ulen = ntohs(up->uh_ulen);
	if ( ulen != len )
		adapter->Weird("UDP_datagram_length_mismatch", util::fmt("%d != %d", ulen, len));

	len -= sizeof(struct udphdr);
	ulen -= sizeof(struct udphdr);
	remaining -= sizeof(struct udphdr);

	c->SetLastTime(run_state::current_timestamp);

	if ( udp_contents )
		{
		static auto udp_content_ports = id::find_val<TableVal>("udp_content_ports");
		static auto udp_content_delivery_ports_orig = id::find_val<TableVal>("udp_content_delivery_ports_orig");
		static auto udp_content_delivery_ports_resp = id::find_val<TableVal>("udp_content_delivery_ports_resp");
		bool do_udp_contents = false;
		const auto& sport_val = val_mgr->Port(ntohs(up->uh_sport), TRANSPORT_UDP);
		const auto& dport_val = val_mgr->Port(ntohs(up->uh_dport), TRANSPORT_UDP);

		if ( udp_content_ports->FindOrDefault(dport_val) ||
		     udp_content_ports->FindOrDefault(sport_val) )
			do_udp_contents = true;
		else
			{
			uint16_t p = zeek::detail::udp_content_delivery_ports_use_resp ? c->RespPort()
			                                                               : up->uh_dport;
			const auto& port_val = zeek::val_mgr->Port(ntohs(p), TRANSPORT_UDP);

			if ( is_orig )
				{
				auto result = udp_content_delivery_ports_orig->FindOrDefault(port_val);

				if ( zeek::detail::udp_content_deliver_all_orig || (result && result->AsBool()) )
					do_udp_contents = true;
				}
			else
				{
				auto result = udp_content_delivery_ports_resp->FindOrDefault(port_val);

				if ( zeek::detail::udp_content_deliver_all_resp || (result && result->AsBool()) )
					do_udp_contents = true;
				}
			}

		if ( do_udp_contents )
			adapter->EnqueueConnEvent(udp_contents,
			                     adapter->ConnVal(),
			                     val_mgr->Bool(is_orig),
			                     make_intrusive<StringVal>(len, (const char*) data));
		}

	if ( is_orig )
		{
		c->CheckHistory(HIST_ORIG_DATA_PKT, 'D');
		adapter->UpdateLength(is_orig, ulen);
		adapter->Event(udp_request);
		}
	else
		{
		c->CheckHistory(HIST_RESP_DATA_PKT, 'd');
		adapter->UpdateLength(is_orig, ulen);
		adapter->Event(udp_reply);
		}

	// Send the packet back into the packet analysis framework.
	ForwardPacket(len, data, pkt);

	// Also try sending it into session analysis.
	if ( remaining >= len )
		adapter->ForwardPacket(len, data, is_orig, -1, ip.get(), remaining);
	}

bool UDPAnalyzer::ValidateChecksum(const IP_Hdr* ip, const udphdr* up, int len)
	{
	auto sum = detail::ip_in_cksum(ip->IP4_Hdr(), ip->SrcAddr(), ip->DstAddr(),
	                               IPPROTO_UDP,
	                               reinterpret_cast<const uint8_t*>(up), len);

	return sum == 0xffff;
	}
