// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "zeek-config.h"

#include "Net.h"
#include "NetVar.h"
#include "analyzer/protocol/udp/UDP.h"
#include "analyzer/Manager.h"
#include "Reporter.h"
#include "Conn.h"

#include "events.bif.h"

using namespace analyzer::udp;

UDP_Analyzer::UDP_Analyzer(Connection* conn)
: TransportLayerAnalyzer("UDP", conn)
	{
	conn->EnableStatusUpdateTimer();
	conn->SetInactivityTimeout(udp_inactivity_timeout);
	request_len = reply_len = -1;	// -1 means "haven't seen any activity"

	req_chk_cnt = rep_chk_cnt = 0;
	req_chk_thresh = rep_chk_thresh = 1;
	}

UDP_Analyzer::~UDP_Analyzer()
	{
	// XXX: need to implement this!
	// delete src_pkt_writer;
	}

void UDP_Analyzer::Init()
	{
	}

void UDP_Analyzer::Done()
	{
	Analyzer::Done();
	}

void UDP_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig,
					uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	assert(ip);

	Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	const struct udphdr* up = (const struct udphdr*) data;

	// Increment data before checksum check so that data will
	// point to UDP payload even if checksum fails. Particularly,
	// it allows event packet_contents to get to the data.
	data += sizeof(struct udphdr);

	// We need the min() here because Ethernet frame padding can lead to
	// caplen > len.
	if ( packet_contents )
		PacketContents(data, std::min(len, caplen) - sizeof(struct udphdr));

	int chksum = up->uh_sum;

	auto validate_checksum = ! current_pkt->l3_checksummed && ! ignore_checksums && caplen >=len;
	constexpr auto vxlan_len = 8;
	constexpr auto eth_len = 14;

	if ( validate_checksum &&
	     len > ((int)sizeof(struct udphdr) + vxlan_len + eth_len) &&
	     (data[0] & 0x08) == 0x08 )
		{
		auto& vxlan_ports = analyzer_mgr->GetVxlanPorts();

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
			if ( chksum && ! ValidateChecksum(ip, up, len) )
				bad = true;
			}

		/* checksum is not optional for IPv6 */
		else if ( ! ValidateChecksum(ip, up, len) )
			bad = true;

		if ( bad )
			{
			Weird("bad_UDP_checksum");

			if ( is_orig )
				{
				uint32_t t = req_chk_thresh;
				if ( Conn()->ScaledHistoryEntry('C', req_chk_cnt,
				                                req_chk_thresh) )
					ChecksumEvent(is_orig, t);
				}
			else
				{
				uint32_t t = rep_chk_thresh;
				if ( Conn()->ScaledHistoryEntry('c', rep_chk_cnt,
				                                rep_chk_thresh) )
					ChecksumEvent(is_orig, t);
				}

			return;
			}
		}

	int ulen = ntohs(up->uh_ulen);
	if ( ulen != len )
		Weird("UDP_datagram_length_mismatch", fmt("%d != %d", ulen, len));

	len -= sizeof(struct udphdr);
	ulen -= sizeof(struct udphdr);
	caplen -= sizeof(struct udphdr);

	Conn()->SetLastTime(current_timestamp);

	if ( udp_contents )
		{
		static auto udp_content_ports = zeek::lookup_val<TableVal>("udp_content_ports");
		static auto udp_content_delivery_ports_orig = zeek::lookup_val<TableVal>("udp_content_delivery_ports_orig");
		static auto udp_content_delivery_ports_resp = zeek::lookup_val<TableVal>("udp_content_delivery_ports_resp");
		bool do_udp_contents = false;
		const auto& sport_val = val_mgr->Port(ntohs(up->uh_sport), TRANSPORT_UDP);
		const auto& dport_val = val_mgr->Port(ntohs(up->uh_dport), TRANSPORT_UDP);

		if ( udp_content_ports->Lookup(dport_val.get()) ||
		     udp_content_ports->Lookup(sport_val.get()) )
			do_udp_contents = true;
		else
			{
			uint16_t p = udp_content_delivery_ports_use_resp ? Conn()->RespPort()
			                                                 : up->uh_dport;
			const auto& port_val = val_mgr->Port(ntohs(p), TRANSPORT_UDP);

			if ( is_orig )
				{
				auto result = udp_content_delivery_ports_orig->Lookup(port_val.get());

				if ( udp_content_deliver_all_orig || (result && result->AsBool()) )
					do_udp_contents = true;
				}
			else
				{
				auto result = udp_content_delivery_ports_resp->Lookup(port_val.get());

				if ( udp_content_deliver_all_resp || (result && result->AsBool()) )
					do_udp_contents = true;
				}
			}

		if ( do_udp_contents )
			EnqueueConnEvent(udp_contents,
				ConnVal(),
				val_mgr->Bool(is_orig),
				make_intrusive<StringVal>(len, (const char*) data)
			);
		}

	if ( is_orig )
		{
		Conn()->CheckHistory(HIST_ORIG_DATA_PKT, 'D');

		if ( request_len < 0 )
			request_len = ulen;
		else
			{
			request_len += ulen;
#ifdef DEBUG
			if ( request_len < 0 )
				reporter->Warning("wrapping around for UDP request length");
#endif
			}

		Event(udp_request);
		}

	else
		{
		Conn()->CheckHistory(HIST_RESP_DATA_PKT, 'd');

		if ( reply_len < 0 )
			reply_len = ulen;
		else
			{
			reply_len += ulen;
#ifdef DEBUG
			if ( reply_len < 0 )
				reporter->Warning("wrapping around for UDP reply length");
#endif
			}

		Event(udp_reply);
		}

	if ( caplen >= len )
		ForwardPacket(len, data, is_orig, seq, ip, caplen);
	}

void UDP_Analyzer::UpdateConnVal(RecordVal *conn_val)
	{
	RecordVal *orig_endp = conn_val->Lookup("orig")->AsRecordVal();
	RecordVal *resp_endp = conn_val->Lookup("resp")->AsRecordVal();

	UpdateEndpointVal(orig_endp, true);
	UpdateEndpointVal(resp_endp, false);

	// Call children's UpdateConnVal
	Analyzer::UpdateConnVal(conn_val);
	}

void UDP_Analyzer::UpdateEndpointVal(RecordVal* endp, bool is_orig)
	{
	bro_int_t size = is_orig ? request_len : reply_len;
	if ( size < 0 )
		{
		endp->Assign(0, val_mgr->Count(0));
		endp->Assign(1, val_mgr->Count(int(UDP_INACTIVE)));
		}

	else
		{
		endp->Assign(0, val_mgr->Count(size));
		endp->Assign(1, val_mgr->Count(int(UDP_ACTIVE)));
		}
	}

bool UDP_Analyzer::IsReuse(double /* t */, const u_char* /* pkt */)
	{
	return false;
	}

unsigned int UDP_Analyzer::MemoryAllocation() const
	{
	// A rather low lower bound....
	return Analyzer::MemoryAllocation() + padded_sizeof(*this) - 24;
	}

void UDP_Analyzer::ChecksumEvent(bool is_orig, uint32_t threshold)
	{
	Conn()->HistoryThresholdEvent(udp_multiple_checksum_errors,
	                              is_orig, threshold);
	}

bool UDP_Analyzer::ValidateChecksum(const IP_Hdr* ip, const udphdr* up, int len)
	{
	uint32_t sum;

	if ( len % 2 == 1 )
		// Add in pad byte.
		sum = htons(((const u_char*) up)[len - 1] << 8);
	else
		sum = 0;

	sum = ones_complement_checksum(ip->SrcAddr(), sum);
	sum = ones_complement_checksum(ip->DstAddr(), sum);
	// Note, for IPv6, strictly speaking the protocol and length fields are
	// 32 bits rather than 16 bits.  But because the upper bits are all zero,
	// we get the same checksum either way.
	sum += htons(IPPROTO_UDP);
	sum += htons((unsigned short) len);
	sum = ones_complement_checksum((void*) up, len, sum);

	return sum == 0xffff;
	}
