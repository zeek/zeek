#include "SIP.h"

#include "events.bif.h"

using namespace analyzer::sip;

SIP_Analyzer::SIP_Analyzer(Connection* c)
: analyzer::Analyzer("SIP", c)
	{
	interp = new binpac::SIP::SIP_Conn(this);
	}

SIP_Analyzer::~SIP_Analyzer()
	{
	delete interp;
	}

void SIP_Analyzer::Done()
	{
	Analyzer::Done();
	}

void SIP_Analyzer::DeliverPacket(int len, const u_char* data,
				 bool orig, int seq, const IP_Hdr* ip, int caplen)
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
