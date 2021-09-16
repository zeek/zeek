// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/ayiya/AYIYA.h"

#include "zeek/Func.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

namespace zeek::analyzer::ayiya
	{

AYIYA_Analyzer::AYIYA_Analyzer(Connection* conn) : Analyzer("AYIYA", conn)
	{
	interp = new binpac::AYIYA::AYIYA_Conn(this);
	}

AYIYA_Analyzer::~AYIYA_Analyzer()
	{
	delete interp;
	}

void AYIYA_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void AYIYA_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                                   const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}

	if ( inner_packet_offset <= 0 )
		return;

	data += inner_packet_offset;
	len -= inner_packet_offset;
	caplen -= inner_packet_offset;
	inner_packet_offset = -1;

	std::unique_ptr<IP_Hdr> inner;
	int result = packet_analysis::IP::ParsePacket(len, data, next_header, inner);

	if ( result == 0 )
		{
		ProtocolConfirmation();
	std:
		shared_ptr<EncapsulationStack> e = Conn()->GetEncapsulation();
		EncapsulatingConn ec(Conn(), BifEnum::Tunnel::AYIYA);
		packet_analysis::IPTunnel::ip_tunnel_analyzer->ProcessEncapsulatedPacket(
			run_state::network_time, nullptr, inner, e, ec);
		}
	else if ( result == -2 )
		ProtocolViolation("AYIYA next header internal mismatch",
		                  reinterpret_cast<const char*>(data), len);
	else if ( result < 0 )
		ProtocolViolation("Truncated AYIYA", reinterpret_cast<const char*>(data), len);
	else
		ProtocolViolation("AYIYA payload length", reinterpret_cast<const char*>(data), len);
	}

	} // namespace zeek::analyzer::ayiya
