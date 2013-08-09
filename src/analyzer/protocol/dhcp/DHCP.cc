#include "DHCP.h"

#include "events.bif.h"

using namespace analyzer::dhcp;

DHCP_Analyzer::DHCP_Analyzer(Connection* conn)
: Analyzer("DHCP", conn)
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

void DHCP_Analyzer::DeliverPacket(int len, const u_char* data,
			bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}
