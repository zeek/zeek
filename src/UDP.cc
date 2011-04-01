// $Id: UDP.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Net.h"
#include "NetVar.h"
#include "UDP.h"

UDP_Analyzer::UDP_Analyzer(Connection* conn)
: TransportLayerAnalyzer(AnalyzerTag::UDP, conn)
	{
	conn->EnableStatusUpdateTimer();
	conn->SetInactivityTimeout(udp_inactivity_timeout);
	request_len = reply_len = -1;	// -1 means "haven't seen any activity"
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
					int seq, const IP_Hdr* ip, int caplen)
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
		PacketContents(data, min(len, caplen) - sizeof(struct udphdr));

	int chksum = up->uh_sum;

	if ( ! ignore_checksums && caplen >= len )
		{
		bool bad = false;

		if ( ip->IP4_Hdr() && chksum &&
		     udp_checksum(ip->IP4_Hdr(), up, len) != 0xffff )
			bad = true;

#ifdef BROv6
		if ( ip->IP6_Hdr() && /* checksum is not optional for IPv6 */
		     udp6_checksum(ip->IP6_Hdr(), up, len) != 0xffff )
			bad = true;
#endif

		if ( bad )
			{
			Weird("bad_UDP_checksum");

			if ( is_orig )
				Conn()->CheckHistory(HIST_ORIG_CORRUPT_PKT, 'C');
			else
				Conn()->CheckHistory(HIST_RESP_CORRUPT_PKT, 'c');

			return;
			}
		}

	int ulen = ntohs(up->uh_ulen);
	if ( ulen != len )
		Weird(fmt("UDP_datagram_length_mismatch(%d!=%d)", ulen, len));

	len -= sizeof(struct udphdr);
	ulen -= sizeof(struct udphdr);
	caplen -= sizeof(struct udphdr);

	Conn()->SetLastTime(current_timestamp);

	if ( udp_contents )
		{
		PortVal port_val(ntohs(up->uh_dport), TRANSPORT_UDP);
		Val* result = 0;
		bool do_udp_contents = false;

		if ( is_orig )
			{
			result = udp_content_delivery_ports_orig->Lookup(
								&port_val);
			if ( udp_content_deliver_all_orig ||
			     (result && result->AsBool()) )
				do_udp_contents = true;
			}
		else
			{
			result = udp_content_delivery_ports_resp->Lookup(
								&port_val);
			if ( udp_content_deliver_all_resp ||
			     (result && result->AsBool()) )
				do_udp_contents = true;
			}

		if ( do_udp_contents )
			{
			val_list* vl = new val_list;
			vl->append(BuildConnVal());
			vl->append(new Val(is_orig, TYPE_BOOL));
			vl->append(new StringVal(len, (const char*) data));
			ConnectionEvent(udp_contents, vl);
			}
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
				warn("wrapping around for UDP request length");
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
				warn("wrapping around for UDP reply length");
#endif
			}

		Event(udp_reply);
		}

	if ( caplen >= len )
		ForwardPacket(len, data, is_orig, seq, ip, caplen);
	}

void UDP_Analyzer::UpdateEndpointVal(RecordVal* endp, int is_orig)
	{
	bro_int_t size = is_orig ? request_len : reply_len;
	if ( size < 0 )
		{
		endp->Assign(0, new Val(0, TYPE_COUNT));
		endp->Assign(1, new Val(int(UDP_INACTIVE), TYPE_COUNT));
		}

	else
		{
		endp->Assign(0, new Val(size, TYPE_COUNT));
		endp->Assign(1, new Val(int(UDP_ACTIVE), TYPE_COUNT));
		}
	}

bool UDP_Analyzer::IsReuse(double /* t */, const u_char* /* pkt */)
	{
	return 0;
	}

unsigned int UDP_Analyzer::MemoryAllocation() const
	{
	// A rather low lower bound....
	return Analyzer::MemoryAllocation() + padded_sizeof(*this) - 24;
	}


