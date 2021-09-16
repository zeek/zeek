// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/IP.h"

#include "zeek/Discard.h"
#include "zeek/Event.h"
#include "zeek/Frag.h"
#include "zeek/IP.h"
#include "zeek/IPAddr.h"
#include "zeek/NetVar.h"
#include "zeek/PacketFilter.h"
#include "zeek/RunState.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::IP;

IPAnalyzer::IPAnalyzer() : zeek::packet_analysis::Analyzer("IP")
	{
	discarder = new detail::Discarder();
	if ( ! discarder->IsActive() )
		{
		delete discarder;
		discarder = nullptr;
		}
	}

IPAnalyzer::~IPAnalyzer()
	{
	delete discarder;
	}

bool IPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Check to make sure we have enough data left for an IP header to be here. Note we only
	// check ipv4 here. We'll check ipv6 later once we determine we have an ipv6 header.
	if ( len < sizeof(struct ip) )
		{
		Weird("truncated_IP", packet);
		return false;
		}

	int32_t hdr_size = static_cast<int32_t>(data - packet->data);

	// Cast the current data pointer to an IP header pointer so we can use it to get some
	// data about the header.
	auto ip = (const struct ip*)data;
	uint32_t protocol = ip->ip_v;

	// This is a unique pointer because of the mass of early returns from this method.
	if ( protocol == 4 )
		{
		packet->ip_hdr = std::make_unique<IP_Hdr>(ip, false);
		packet->l3_proto = L3_IPV4;
		}
	else if ( protocol == 6 )
		{
		if ( len < sizeof(struct ip6_hdr) )
			{
			Weird("truncated_IP", packet);
			return false;
			}

		packet->ip_hdr = std::make_unique<IP_Hdr>((const struct ip6_hdr*)data, false, len);
		packet->l3_proto = L3_IPV6;
		}
	else
		{
		Weird("unknown_ip_version", packet);
		return false;
		}

	const struct ip* ip4 = packet->ip_hdr->IP4_Hdr();

	// TotalLen() returns the full length of the IP portion of the packet, including
	// the IP header and payload.
	uint32_t total_len = packet->ip_hdr->TotalLen();
	if ( total_len == 0 )
		{
		// TCP segmentation offloading can zero out the ip_len field.
		Weird("ip_hdr_len_zero", packet);

		// Cope with the zero'd out ip_len field by using the caplen.
		total_len = packet->cap_len - hdr_size;
		}

	if ( packet->len < total_len + hdr_size )
		{
		Weird("truncated_IPv6", packet);
		return false;
		}

	// For both of these it is safe to pass ip_hdr because the presence
	// is guaranteed for the functions that pass data to us.
	uint16_t ip_hdr_len = packet->ip_hdr->HdrLen();
	if ( ip_hdr_len > total_len )
		{
		Weird("invalid_IP_header_size", packet);
		return false;
		}

	if ( ip_hdr_len > len )
		{
		Weird("internally_truncated_header", packet);
		return false;
		}

	if ( packet->ip_hdr->IP4_Hdr() )
		{
		if ( ip_hdr_len < sizeof(struct ip) )
			{
			Weird("IPv4_min_header_size", packet);
			return false;
			}
		}
	else
		{
		if ( ip_hdr_len < sizeof(struct ip6_hdr) )
			{
			Weird("IPv6_min_header_size", packet);
			return false;
			}
		}

	// Ignore if packet matches packet filter.
	detail::PacketFilter* packet_filter = packet_mgr->GetPacketFilter(false);
	if ( packet_filter && packet_filter->Match(packet->ip_hdr, total_len, len) )
		return false;

	if ( ! packet->l2_checksummed && ! detail::ignore_checksums && ip4 &&
	     ! IPBasedAnalyzer::GetIgnoreChecksumsNets()->Contains(packet->ip_hdr->IPHeaderSrcAddr()) &&
	     detail::in_cksum(reinterpret_cast<const uint8_t*>(ip4), ip_hdr_len) != 0xffff )
		{
		Weird("bad_IP_checksum", packet);
		return false;
		}

	if ( discarder && discarder->NextPacket(packet->ip_hdr, total_len, len) )
		return false;

	detail::FragReassembler* f = nullptr;

	if ( packet->ip_hdr->IsFragment() )
		{
		packet->dump_packet = true; // always record fragments

		if ( len < total_len )
			{
			Weird("incompletely_captured_fragment", packet);

			// Don't try to reassemble, that's doomed.
			// Discard all except the first fragment (which
			// is useful in analyzing header-only traces)
			if ( packet->ip_hdr->FragOffset() != 0 )
				return false;
			}
		else
			{
			f = detail::fragment_mgr->NextFragment(run_state::processing_start_time, packet->ip_hdr,
			                                       packet->data + hdr_size);
			std::unique_ptr<IP_Hdr> ih = f->ReassembledPkt();

			if ( ! ih )
				// It didn't reassemble into anything yet.
				return true;

			ip4 = ih->IP4_Hdr();

			// Switch the stored ip header over to the one from the
			// fragmented packet.
			packet->ip_hdr = std::move(ih);

			len = total_len = packet->ip_hdr->TotalLen();
			ip_hdr_len = packet->ip_hdr->HdrLen();
			packet->cap_len = total_len + hdr_size;

			if ( ip_hdr_len > total_len )
				{
				Weird("invalid_IP_header_size", packet);
				return false;
				}
			}
		}

	detail::FragReassemblerTracker frt(f);

	// We stop building the chain when seeing IPPROTO_ESP so if it's
	// there, it's always the last.
	if ( packet->ip_hdr->LastHeader() == IPPROTO_ESP )
		{
		packet->dump_packet = true;
		if ( esp_packet )
			event_mgr.Enqueue(esp_packet, packet->ip_hdr->ToPktHdrVal());

		// Can't do more since upper-layer payloads are going to be encrypted.
		return true;
		}

	// We stop building the chain when seeing IPPROTO_MOBILITY so it's always
	// last if present.
	if ( packet->ip_hdr->LastHeader() == IPPROTO_MOBILITY )
		{
		packet->dump_packet = true;

		if ( ! detail::ignore_checksums &&
		     mobility_header_checksum(packet->ip_hdr.get()) != 0xffff )
			{
			Weird("bad_MH_checksum", packet);
			return false;
			}

		if ( mobile_ipv6_message )
			event_mgr.Enqueue(mobile_ipv6_message, packet->ip_hdr->ToPktHdrVal());

		if ( packet->ip_hdr->NextProto() != IPPROTO_NONE )
			Weird("mobility_piggyback", packet);

		return true;
		}

	// Set the data pointer to match the payload from the IP header. This makes sure that it's also
	// pointing at the reassembled data for a fragmented packet.
	data = packet->ip_hdr->Payload();
	len -= ip_hdr_len;

	// Session analysis assumes that the header size stored in the packet does not include the IP
	// header size. There are two reasons for this: 1) Packet::ToRawPktHdrVal() wants to look at the
	// IP header for reporting, and 2) The VXLAN analyzer uses the header position to create the
	// next packet in the tunnel chain. Once the TCP/UDP work is done and the VXLAN analyzer can
	// move into packet analysis, this can change, but for now we leave it as it is.

	bool return_val = true;
	int proto = packet->ip_hdr->NextProto();

	packet->proto = proto;

	// Double check the lengths one more time before forwarding this on.
	if ( packet->ip_hdr->TotalLen() < packet->ip_hdr->HdrLen() )
		{
		Weird("bogus_IP_header_lengths", packet);
		return false;
		}

	switch ( proto )
		{
		case IPPROTO_NONE:
			// If the packet is encapsulated in Teredo, then it was a bubble and
			// the Teredo analyzer may have raised an event for that, else we're
			// not sure the reason for the No Next header in the packet.
			if ( ! (packet->encap && packet->encap->LastType() == BifEnum::Tunnel::TEREDO) )
				{
				Weird("ipv6_no_next", packet);
				return_val = false;
				}
			break;
		default:
			packet->proto = proto;

			// For everything else, pass it on to another analyzer. If there's no one to handle
			// that, it'll report a Weird.
			return_val = ForwardPacket(len, data, packet, proto);
			break;
		}

	if ( f )
		f->DeleteTimer();

	return return_val;
	}

int zeek::packet_analysis::IP::ParsePacket(int caplen, const u_char* const pkt, int proto,
                                           std::unique_ptr<zeek::IP_Hdr>& inner)
	{
	if ( proto == IPPROTO_IPV6 )
		{
		if ( caplen < (int)sizeof(struct ip6_hdr) )
			return -1;

		const struct ip6_hdr* ip6 = (const struct ip6_hdr*)pkt;
		inner = std::make_unique<zeek::IP_Hdr>(ip6, false, caplen);
		if ( (ip6->ip6_ctlun.ip6_un2_vfc & 0xF0) != 0x60 )
			return -2;
		}

	else if ( proto == IPPROTO_IPV4 )
		{
		if ( caplen < (int)sizeof(struct ip) )
			return -1;

		const struct ip* ip4 = (const struct ip*)pkt;
		inner = std::make_unique<zeek::IP_Hdr>(ip4, false);
		if ( ip4->ip_v != 4 )
			return -2;
		}

	else
		{
		zeek::reporter->InternalWarning("Bad IP protocol version in IP::ParsePacket");
		return -1;
		}

	if ( (uint32_t)caplen != inner->TotalLen() )
		return (uint32_t)caplen < inner->TotalLen() ? -1 : 1;

	return 0;
	}
