// See the file  in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/vxlan/VXLAN.h"

extern "C"
	{
#include <pcap.h> // for the DLT_EN10MB constant definition
	}

#include "zeek/Conn.h"
#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/analyzer/protocol/vxlan/events.bif.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

namespace zeek::analyzer::vxlan
	{

void VXLAN_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void VXLAN_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                                   const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	// Outer Ethernet, IP, and UDP layers already skipped.
	// Also, generic UDP analyzer already checked/guarantees caplen >= len.

	constexpr auto vxlan_len = 8;

	if ( len < vxlan_len )
		{
		ProtocolViolation("VXLAN header truncation", (const char*)data, len);
		return;
		}

	if ( (data[0] & 0x08) == 0 )
		{
		ProtocolViolation("VXLAN 'I' flag not set", (const char*)data, len);
		return;
		}

	std::shared_ptr<EncapsulationStack> outer = Conn()->GetEncapsulation();

	if ( outer && outer->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("tunnel_depth");
		return;
		}

	if ( ! outer )
		outer = std::make_shared<EncapsulationStack>();

	EncapsulatingConn inner(Conn(), BifEnum::Tunnel::VXLAN);
	outer->Add(inner);

	int vni = (data[4] << 16) + (data[5] << 8) + (data[6] << 0);

	// Skip over the VXLAN header and create a new packet.
	data += vxlan_len;
	caplen -= vxlan_len;
	len -= vxlan_len;

	pkt_timeval ts;
	ts.tv_sec = (time_t)run_state::current_timestamp;
	ts.tv_usec = (suseconds_t)((run_state::current_timestamp - (double)ts.tv_sec) * 1000000);
	Packet pkt(DLT_EN10MB, &ts, caplen, len, data);
	pkt.encap = outer;

	if ( ! packet_mgr->ProcessInnerPacket(&pkt) )
		{
		ProtocolViolation("VXLAN invalid inner packet");
		return;
		}

	// This isn't really an error. It's just that the inner packet wasn't an IP packet (like ARP).
	// Just return without reporting a violation.
	if ( ! pkt.ip_hdr )
		return;

	ProtocolConfirmation();

	if ( vxlan_packet )
		Conn()->EnqueueEvent(vxlan_packet, nullptr, ConnVal(), pkt.ip_hdr->ToPktHdrVal(),
		                     val_mgr->Count(vni));
	}

	} // namespace zeek::analyzer::vxlan
