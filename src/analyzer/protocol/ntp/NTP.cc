#include "NTP.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::NTP;

NTP_Analyzer::NTP_Analyzer(Connection* c)
	: analyzer::Analyzer("NTP", c)
	{
	interp = new binpac::NTP::NTP_Conn(this);
	}

void NTP_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

NTP_Analyzer::~NTP_Analyzer()
	{
	delete interp;
	}

void NTP_Analyzer::DeliverPacket(uint64_t len, const u_char* data, bool orig,
                                 uint64_t seq, const IP_Hdr* ip, uint64_t caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
