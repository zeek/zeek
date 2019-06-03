#include "NTP.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::NTP;

NTP_Analyzer::NTP_Analyzer(Connection* c)
	: analyzer::Analyzer("NTP", c)
	{
	interp = new binpac::NTP::NTP_Conn(this);
	}

NTP_Analyzer::~NTP_Analyzer()
	{
	delete interp;
	}

void NTP_Analyzer::Done()
	{
	Analyzer::Done();
	}

void NTP_Analyzer::DeliverPacket(int len, const u_char* data,
				    bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
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
