// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/udp/UDP.h"
#include "zeek/RunState.h"
#include "zeek/Conn.h"
#include "zeek/session/Manager.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

#include "zeek/packet_analysis/protocol/udp/events.bif.h"

using namespace zeek::packet_analysis::UDP;
using namespace zeek::packet_analysis::IP;

constexpr uint32_t HIST_ORIG_DATA_PKT = 0x1;
constexpr uint32_t HIST_RESP_DATA_PKT = 0x2;
constexpr uint32_t HIST_ORIG_CORRUPT_PKT = 0x4;
constexpr uint32_t HIST_RESP_CORRUPT_PKT = 0x8;

enum UDP_EndpointState {
	UDP_INACTIVE,	// no packet seen
	UDP_ACTIVE,		// packets seen
};

UDPAnalyzer::UDPAnalyzer() : IPBasedAnalyzer("UDP", TRANSPORT_UDP, UDP_PORT_MASK, false)
	{
	// TODO: remove once the other plugins are done
	new_plugin = true;
	}

UDPAnalyzer::~UDPAnalyzer()
	{
	}

bool UDPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	uint32_t min_hdr_len = sizeof(struct udphdr);
	if ( ! CheckHeaderTrunc(min_hdr_len, len, packet) )
		return false;

	ConnTuple id;
	id.src_addr = packet->ip_hdr->SrcAddr();
	id.dst_addr = packet->ip_hdr->DstAddr();
	const struct udphdr* up = (const struct udphdr *) packet->ip_hdr->Payload();
	id.src_port = up->uh_sport;
	id.dst_port = up->uh_dport;
	id.is_one_way = false;
	id.proto = TRANSPORT_UDP;

	ProcessConnection(id, packet, len);

	return true;
	}

void UDPAnalyzer::CreateTransportAnalyzer(Connection* conn, IPBasedTransportAnalyzer*& root,
                                          analyzer::pia::PIA*& pia, bool& check_port)
	{
	root = new UDPTransportAnalyzer(conn);
	root->SetParent(this);

	conn->EnableStatusUpdateTimer();
	conn->SetInactivityTimeout(zeek::detail::udp_inactivity_timeout);

	pia = new analyzer::pia::PIA_UDP(conn);
	check_port = true;
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

void UDPAnalyzer::ContinueProcessing(Connection* c, double t, bool is_orig, int remaining, Packet* pkt)
	{
	conn = c;

	auto* ta = static_cast<UDPTransportAnalyzer*>(conn->GetRootAnalyzer());

	const u_char* data = pkt->ip_hdr->Payload();
	int len = pkt->ip_hdr->PayloadLen();

	const struct udphdr* up = (const struct udphdr*) data;
	const std::unique_ptr<IP_Hdr>& ip = pkt->ip_hdr;

	ta->DeliverPacket(len, data, is_orig, -1, ip.get(), remaining);

	// Increment data before checksum check so that data will
	// point to UDP payload even if checksum fails. Particularly,
	// it allows event packet_contents to get to the data.
	data += sizeof(struct udphdr);

	// We need the min() here because Ethernet frame padding can lead to
	// remaining > len.
	if ( packet_contents )
		ta->PacketContents(data, std::min(len, remaining) - sizeof(struct udphdr));

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
			ta->Weird("bad_UDP_checksum");

			if ( is_orig )
				{
				uint32_t t = ta->req_chk_thresh;

				if ( conn->ScaledHistoryEntry('C',
				                              ta->req_chk_cnt,
				                              ta->req_chk_thresh) )
					ChecksumEvent(is_orig, t);
				}
			else
				{
				uint32_t t = ta->rep_chk_thresh;

				if ( conn->ScaledHistoryEntry('c',
				                              ta->rep_chk_cnt,
				                              ta->rep_chk_thresh) )
					ChecksumEvent(is_orig, t);
				}

			return;
			}
		}

	int ulen = ntohs(up->uh_ulen);
	if ( ulen != len )
		ta->Weird("UDP_datagram_length_mismatch", util::fmt("%d != %d", ulen, len));

	len -= sizeof(struct udphdr);
	ulen -= sizeof(struct udphdr);
	remaining -= sizeof(struct udphdr);

	conn->SetLastTime(run_state::current_timestamp);

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
			uint16_t p = zeek::detail::udp_content_delivery_ports_use_resp ? conn->RespPort()
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
			ta->EnqueueConnEvent(udp_contents,
			                     ta->ConnVal(),
			                     val_mgr->Bool(is_orig),
			                     make_intrusive<StringVal>(len, (const char*) data));
		}

	if ( is_orig )
		{
		conn->CheckHistory(HIST_ORIG_DATA_PKT, 'D');
		ta->UpdateLength(is_orig, ulen);
		ta->Event(udp_request);
		}
	else
		{
		conn->CheckHistory(HIST_RESP_DATA_PKT, 'd');
		ta->UpdateLength(is_orig, ulen);
		ta->Event(udp_reply);
		}

	// Send the packet back into the packet analysis framework.
	ForwardPacket(len, data, pkt);

	// Also try sending it into session analysis.
	if ( remaining >= len )
		ta->ForwardPacket(len, data, is_orig, -1, ip.get(), remaining);

	conn = nullptr;
	}

bool UDPAnalyzer::ValidateChecksum(const IP_Hdr* ip, const udphdr* up, int len)
	{
	auto sum = detail::ip_in_cksum(ip->IP4_Hdr(), ip->SrcAddr(), ip->DstAddr(),
	                               IPPROTO_UDP,
	                               reinterpret_cast<const uint8_t*>(up), len);

	return sum == 0xffff;
	}

void UDPAnalyzer::ChecksumEvent(bool is_orig, uint32_t threshold)
	{
	conn->HistoryThresholdEvent(udp_multiple_checksum_errors, is_orig, threshold);
	}

void UDPTransportAnalyzer::AddExtraAnalyzers(Connection* conn)
	{
	static analyzer::Tag analyzer_connsize = analyzer_mgr->GetComponentTag("CONNSIZE");

	if ( analyzer_mgr->IsEnabled(analyzer_connsize) )
		// Add ConnSize analyzer. Needs to see packets, not stream.
		AddChildAnalyzer(new analyzer::conn_size::ConnSize_Analyzer(conn));
	}

void UDPTransportAnalyzer::UpdateConnVal(RecordVal* conn_val)
	{
	auto orig_endp = conn_val->GetField("orig");
	auto resp_endp = conn_val->GetField("resp");

	UpdateEndpointVal(orig_endp, true);
	UpdateEndpointVal(resp_endp, false);

	// Call children's UpdateConnVal
	Analyzer::UpdateConnVal(conn_val);
	}

void UDPTransportAnalyzer::UpdateEndpointVal(const ValPtr& endp_arg, bool is_orig)
	{
	bro_int_t size = is_orig ? request_len : reply_len;
	auto endp = endp_arg->AsRecordVal();

	if ( size < 0 )
		{
		endp->Assign(0, val_mgr->Count(0));
		endp->Assign(1, UDP_INACTIVE);
		}

	else
		{
		endp->Assign(0, static_cast<uint64_t>(size));
		endp->Assign(1, UDP_ACTIVE);
		}
	}

void UDPTransportAnalyzer::UpdateLength(bool is_orig, int len)
	{
	if ( is_orig )
		{
		if ( request_len < 0 )
			request_len = len;
		else
			{
			request_len += len;
#ifdef DEBUG
			if ( request_len < 0 )
				reporter->Warning("wrapping around for UDP request length");
#endif
			}
		}
	else
		{
		if ( reply_len < 0 )
			reply_len = len;
		else
			{
			reply_len += len;
#ifdef DEBUG
			if ( reply_len < 0 )
				reporter->Warning("wrapping around for UDP reply length");
#endif
			}
		}
	}
