// See the file  in the main distribution directory for copyright.

#include <pcap.h>	// for the DLT_EN10MB constant definition

#include "VXLAN.h"
#include "TunnelEncapsulation.h"
#include "Conn.h"
#include "IP.h"
#include "Net.h"
#include "Sessions.h"
#include "Reporter.h"

#include "events.bif.h"

extern "C" {
#include <pcap.h>
}

namespace zeek::analyzer::vxlan {

void VXLAN_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void VXLAN_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                   uint64_t seq, const zeek::IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	// Outer Ethernet, IP, and UDP layers already skipped.
	// Also, generic UDP analyzer already checked/guarantees caplen >= len.

	constexpr auto vxlan_len = 8;

	if ( len < vxlan_len )
		{
		ProtocolViolation("VXLAN header truncation", (const char*) data, len);
		return;
		}

	if ( (data[0] & 0x08) == 0 )
		{
		ProtocolViolation("VXLAN 'I' flag not set", (const char*) data, len);
		return;
		}

	const zeek::EncapsulationStack* estack = Conn()->GetEncapsulation();

	if ( estack && estack->Depth() >= zeek::BifConst::Tunnel::max_depth )
		{
		zeek::reporter->Weird(Conn(), "tunnel_depth");
		return;
		}

	int vni = (data[4] << 16) + (data[5] << 8) + (data[6] << 0);

	data += vxlan_len;
	caplen -= vxlan_len;
	len -= vxlan_len;

	pkt_timeval ts;
	ts.tv_sec = (time_t) current_timestamp;
	ts.tv_usec = (suseconds_t) ((current_timestamp - (double)ts.tv_sec) * 1000000);
	zeek::Packet pkt(DLT_EN10MB, &ts, caplen, len, data);

	if ( ! pkt.Layer2Valid() )
		{
		ProtocolViolation("VXLAN invalid inner ethernet frame",
		                  (const char*) data, len);
		return;
		}

	data += pkt.hdr_size;
	len -= pkt.hdr_size;
	caplen -= pkt.hdr_size;

	zeek::IP_Hdr* inner = nullptr;
	int res = 0;

	switch ( pkt.l3_proto ) {
		case zeek::L3_IPV4:
			res = zeek::sessions->ParseIPPacket(len, data, IPPROTO_IPV4, inner);
			break;
		case zeek::L3_IPV6:
			res = zeek::sessions->ParseIPPacket(len, data, IPPROTO_IPV6, inner);
			break;
		default:
			return;
	}

	if ( res < 0 )
		{
		delete inner;
		ProtocolViolation("Truncated VXLAN or invalid inner IP",
		                  (const char*) data, len);
		return;
		}

	ProtocolConfirmation();

	if ( vxlan_packet )
		Conn()->EnqueueEvent(vxlan_packet, nullptr, ConnVal(),
		                     inner->ToPktHdrVal(), zeek::val_mgr->Count(vni));

	zeek::EncapsulatingConn ec(Conn(), BifEnum::Tunnel::VXLAN);
	zeek::sessions->DoNextInnerPacket(network_time, &pkt, inner, estack, ec);
	}

} // namespace zeek::analyzer::vxlan
