#include "zeek/analyzer/protocol/dhcp/DHCP.h"

#include "zeek/analyzer/protocol/dhcp/events.bif.h"
#include "zeek/analyzer/protocol/dhcp/types.bif.h"

namespace zeek::analyzer::dhcp
	{

DHCP_Analyzer::DHCP_Analyzer(Connection* conn) : Analyzer("DHCP", conn)
	{
	interp = new binpac::DHCP::DHCP_Conn(this);
	}

DHCP_Analyzer::~DHCP_Analyzer()
	{
	delete interp;
	}

void DHCP_Analyzer::Done()
	{
	Analyzer::Done();
	}

void DHCP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
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

	} // namespace zeek::analyzer::dhcp
