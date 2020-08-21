#include "NTP.h"

#include "Reporter.h"

#include "events.bif.h"

namespace zeek::analyzer::ntp {

NTP_Analyzer::NTP_Analyzer(zeek::Connection* c)
	: zeek::analyzer::Analyzer("NTP", c)
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

void NTP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                 uint64_t seq, const zeek::IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

} // namespace zeek::analyzer::ntp
