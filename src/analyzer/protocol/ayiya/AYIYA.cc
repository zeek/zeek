
#include "AYIYA.h"
#include "Func.h"

namespace zeek::analyzer::ayiya {

AYIYA_Analyzer::AYIYA_Analyzer(Connection* conn)
: Analyzer("AYIYA", conn)
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

void AYIYA_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen)
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

	IP_Hdr* inner = nullptr;
	int result = sessions->ParseIPPacket(len, data, next_header, inner);

	if ( result == 0 )
		{
		ProtocolConfirmation();
		EncapsulatingConn ec(Conn(), BifEnum::Tunnel::AYIYA);
		sessions->DoNextInnerPacket(run_state::network_time, nullptr,
		                            inner, Conn()->GetEncapsulation(), ec);
		}
	else if ( result == -2 )
		ProtocolViolation("AYIYA next header internal mismatch",
		                  reinterpret_cast<const char*>(data), len);
	else if ( result < 0 )
		ProtocolViolation("Truncated AYIYA",
		                  reinterpret_cast<const char*>(data), len);
	else
		ProtocolViolation("AYIYA payload length",
		                  reinterpret_cast<const char*>(data), len);

	if ( result != 0 )
		delete inner;
	}

} // namespace zeek::analyzer::ayiya
