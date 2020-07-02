#include "RDPEUDP.h"
#include "Reporter.h"
#include "events.bif.h"
#include "rdpeudp_pac.h"

using namespace analyzer::rdpeudp;

RDP_Analyzer::RDP_Analyzer(Connection* c)
	: zeek::analyzer::Analyzer("RDPEUDP", c)
	{
	interp = new binpac::RDPEUDP::RDPEUDP_Conn(this);
	}

RDP_Analyzer::~RDP_Analyzer()
	{
	delete interp;
	}

void RDP_Analyzer::Done()
	{
	Analyzer::Done();
	}

void RDP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                 uint64_t seq, const IP_Hdr* ip, int caplen)
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
