// See the file "COPYING" in the main distribution directory for copyright.

#include "IP.h"
#include "zeek/NetVar.h"
#include "zeek/IP.h"
#include "zeek/Discard.h"
#include "zeek/PacketFilter.h"
#include "zeek/Sessions.h"
#include "zeek/RunState.h"
#include "zeek/Frag.h"
#include "zeek/Event.h"
#include "zeek/TunnelEncapsulation.h"

using namespace zeek::packet_analysis::IP;

IPAnalyzer::IPAnalyzer()
	: zeek::packet_analysis::Analyzer("IP")
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
	}

bool IPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	EncapsulationStack* encapsulation = nullptr;
	auto it = packet->key_store.find("encap");
	if ( it != packet->key_store.end() )
		encapsulation = std::any_cast<EncapsulationStack*>(it->second);

	// Check to make sure we have enough data left for an IP header to be here. Note we only
	// check ipv4 here. We'll check ipv6 later once we determine we have an ipv6 header.
	if ( len < sizeof(struct ip) )
		{
		packet->Weird("truncated_IP");
		return false;
		}

	// TODO: i feel like this could be generated as we move along the header hierarchy.
	// TODO: the sessions code expects that the header size does not include the ip header. Should
	// this change?
	packet->hdr_size = static_cast<int32_t>(data - packet->data);

	// Cast the current data pointer to an IP header pointer so we can use it to get some
	// data about the header.
	auto ip = (const struct ip *)data;
	uint32_t protocol = ip->ip_v;

	std::unique_ptr<IP_Hdr> ip_hdr = nullptr;
	if ( protocol == 4 )
		{
		ip_hdr = std::make_unique<IP_Hdr>(ip, false);
		packet->l3_proto = L3_IPV4;
		}
	else if ( protocol == 6 )
		{
		if ( len < sizeof(struct ip6_hdr) )
			{
			packet->Weird("truncated_IP");
			return false;
			}

		ip_hdr = std::make_unique<IP_Hdr>((const struct ip6_hdr*) data, false, len);
		packet->l3_proto = L3_IPV6;
		}
	else
		{
		packet->Weird("unknown_ip_version");
		return false;
		}

	const struct ip* ip4 = ip_hdr->IP4_Hdr();

	// total_len is the length of the packet minus all of the headers so far, including IP
	uint32_t total_len = ip_hdr->TotalLen();
	if ( total_len == 0 )
		{
		// TCP segmentation offloading can zero out the ip_len field.
		packet->Weird("ip_hdr_len_zero", encapsulation);

		// Cope with the zero'd out ip_len field by using the caplen.
		total_len = packet->cap_len - packet->hdr_size;
		}

	if ( packet->len < total_len + packet->hdr_size )
		{
		packet->Weird("truncated_IP", encapsulation);
		return false;
		}

	// For both of these it is safe to pass ip_hdr because the presence
	// is guaranteed for the functions that pass data to us.
	uint16_t ip_hdr_len = ip_hdr->HdrLen();
	if ( ip_hdr_len > total_len )
		{
		sessions->Weird("invalid_IP_header_size", ip_hdr.get(), encapsulation);
		return false;
		}

	if ( ip_hdr_len > len )
		{
		sessions->Weird("internally_truncated_header", ip_hdr.get(), encapsulation);
		return false;
		}

	if ( ip_hdr->IP4_Hdr() )
		{
		if ( ip_hdr_len < sizeof(struct ip) )
			{
			packet->Weird("IPv4_min_header_size");
			return false;
			}
		}
	else
		{
		if ( ip_hdr_len < sizeof(struct ip6_hdr) )
			{
			packet->Weird("IPv6_min_header_size");
			return false;
			}
		}

	// Ignore if packet matches packet filter.
	detail::PacketFilter* packet_filter = sessions->GetPacketFilter(false);
	if ( packet_filter && packet_filter->Match(ip_hdr.get(), total_len, len) )
		 return false;

	if ( ! packet->l2_checksummed && ! detail::ignore_checksums && ip4 &&
	     detail::in_cksum(reinterpret_cast<const uint8_t*>(ip4), ip_hdr_len) != 0xffff )
		{
		sessions->Weird("bad_IP_checksum", packet, encapsulation);
		return false;
		}

	if ( discarder && discarder->NextPacket(ip_hdr.get(), total_len, len) )
		return false;

	detail::FragReassembler* f = nullptr;

	if ( ip_hdr->IsFragment() )
		{
		packet->dump_packet = true;	// always record fragments

		if ( len < total_len )
			{
			sessions->Weird("incompletely_captured_fragment", ip_hdr.get(), encapsulation);

			// Don't try to reassemble, that's doomed.
			// Discard all except the first fragment (which
			// is useful in analyzing header-only traces)
			if ( ip_hdr->FragOffset() != 0 )
				return false;
			}
		else
			{
			f = detail::fragment_mgr->NextFragment(run_state::processing_start_time, ip_hdr.get(), packet->data + packet->hdr_size);
			IP_Hdr* ih = f->ReassembledPkt();
			if ( ! ih )
				// It didn't reassemble into anything yet.
				return true;

			ip4 = ih->IP4_Hdr();

			// Delete the old ip_hdr and replace it with this one.
			ip_hdr.reset(ih);

			len = total_len = ip_hdr->TotalLen();
			ip_hdr_len = ip_hdr->HdrLen();
			packet->cap_len = total_len + packet->hdr_size;

			if ( ip_hdr_len > total_len )
				{
				sessions->Weird("invalid_IP_header_size", ip_hdr.get(), encapsulation);
				return false;
				}
			}
		}

	detail::FragReassemblerTracker frt(f);

	// We stop building the chain when seeing IPPROTO_ESP so if it's
	// there, it's always the last.
	if ( ip_hdr->LastHeader() == IPPROTO_ESP )
		{
		packet->dump_packet = true;
		if ( esp_packet )
			event_mgr.Enqueue(esp_packet, ip_hdr->ToPktHdrVal());

		// Can't do more since upper-layer payloads are going to be encrypted.
		return true;
		}

#ifdef ENABLE_MOBILE_IPV6
	// We stop building the chain when seeing IPPROTO_MOBILITY so it's always
	// last if present.
	if ( ip_hdr->LastHeader() == IPPROTO_MOBILITY )
		{
		dump_this_packet = true;

		if ( ! ignore_checksums && mobility_header_checksum(ip_hdr) != 0xffff )
			{
			sessions->Weird("bad_MH_checksum", packet, encapsulation);
			return false;
			}

		if ( mobile_ipv6_message )
			event_mgr.Enqueue(mobile_ipv6_message, ip_hdr->ToPktHdrVal());

		if ( ip_hdr->NextProto() != IPPROTO_NONE )
			sessions->Weird("mobility_piggyback", packet, encapsulation);

		return true;
		}
#endif

	// Set the data pointer to match the payload from the IP header. This makes sure that it's also pointing
	// at the reassembled data for a fragmented packet.
	data = ip_hdr->Payload();
	len -= ip_hdr_len;

	// Session analysis assumes that the header size stored in the packet does not include the IP header
	// size. There are two reasons for this: 1) Packet::ToRawPktHdrVal() wants to look at the IP header for
	// reporting, and 2) The VXLAN analyzer uses the header position to create the next packet in the tunnel
	// chain. Once the TCP/UDP work is done and the VXLAN analyzer can move into packet analysis, this can
	// change, but for now we leave it as it is.

	bool return_val = true;
	int proto = ip_hdr->NextProto();

	switch ( proto ) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		sessions->DoNextPacket(run_state::processing_start_time, packet, ip_hdr.get(), encapsulation);
		break;
	case IPPROTO_NONE:
		// If the packet is encapsulated in Teredo, then it was a bubble and
		// the Teredo analyzer may have raised an event for that, else we're
		// not sure the reason for the No Next header in the packet.
		if ( ! ( encapsulation &&
		         encapsulation->LastType() == BifEnum::Tunnel::TEREDO ) )
			{
			sessions->Weird("ipv6_no_next", packet);
			return_val = false;
			}
		break;
	default:
		// The tunnel analyzer needs this data.
		packet->key_store["ip_hdr"] = ip_hdr.get();
		packet->key_store["proto"] = proto;

		// For everything else, pass it on to another analyzer. If there's no one to handle that,
		// it'll report a Weird.
		return_val = ForwardPacket(len, data, packet, proto);
		break;
	}

	if ( f )
		{
		// If this was a fragment, we need to release the pointer here so that it doesn't get
		// deleted. Deleting this one will be the responsibility of the fragment tracker.
		ip_hdr.release();
		f->DeleteTimer();
		}

	return return_val;
	}
