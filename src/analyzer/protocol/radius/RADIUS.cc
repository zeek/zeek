#include "zeek/analyzer/protocol/radius/RADIUS.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/radius/events.bif.h"

namespace zeek::analyzer::radius
	{

RADIUS_Analyzer::RADIUS_Analyzer(Connection* c) : analyzer::Analyzer("RADIUS", c)
	{
	interp = new binpac::RADIUS::RADIUS_Conn(this);
	}

RADIUS_Analyzer::~RADIUS_Analyzer()
	{
	delete interp;
	}

void RADIUS_Analyzer::Done()
	{
	Analyzer::Done();
	}

void RADIUS_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                                    const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

	} // namespace zeek::analyzer::radius
