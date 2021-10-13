// See the file  in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/geneve/Geneve.h"

#include "zeek/Conn.h"
#include "zeek/IP.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/protocol/geneve/events.bif.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

namespace zeek::analyzer::geneve
	{

void Geneve_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void Geneve_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                                    const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	// Outer Ethernet, IP, and UDP layers already skipped.
	// Also, generic UDP analyzer already checked/guarantees caplen >= len.

	constexpr auto tunnel_header_len = 8;

	if ( len < tunnel_header_len )
		{
		ProtocolViolation("Geneve header truncation", reinterpret_cast<const char*>(data), len);
		return;
		}

	auto outer = Conn()->GetEncapsulation();

	if ( outer && outer->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("tunnel_depth");
		return;
		}

	if ( ! outer )
		outer = std::make_shared<EncapsulationStack>();

	EncapsulatingConn inner(Conn(), BifEnum::Tunnel::GENEVE);
	outer->Add(inner);

	uint8_t tunnel_opt_len = (data[0] & 0x3F) * 4;
	auto vni = (data[4] << 16) + (data[5] << 8) + (data[6] << 0);

	if ( len < tunnel_header_len + tunnel_opt_len )
		{
		ProtocolViolation("Geneve option header truncation", reinterpret_cast<const char*>(data),
		                  len);
		return;
		}

	// Skip over the Geneve headers and create a new packet.
	data += tunnel_header_len + tunnel_opt_len;
	caplen -= tunnel_header_len + tunnel_opt_len;
	len -= tunnel_header_len + tunnel_opt_len;

	pkt_timeval ts;
	ts.tv_sec = static_cast<time_t>(run_state::current_timestamp);
	ts.tv_usec = static_cast<suseconds_t>(
		(run_state::current_timestamp - static_cast<double>(ts.tv_sec)) * 1000000);
	Packet pkt(DLT_EN10MB, &ts, caplen, len, data);
	pkt.encap = outer;

	if ( ! packet_mgr->ProcessInnerPacket(&pkt) )
		{
		ProtocolViolation("Geneve invalid inner packet");
		return;
		}

	// This isn't really an error. It's just that the inner packet wasn't an IP packet (like ARP).
	// Just return without reporting a violation.
	if ( ! pkt.ip_hdr )
		return;

	ProtocolConfirmation();

	if ( geneve_packet )
		Conn()->EnqueueEvent(geneve_packet, nullptr, ConnVal(), pkt.ip_hdr->ToPktHdrVal(),
		                     val_mgr->Count(vni));
	}

	} // namespace zeek::analyzer::geneve
