#include "DHCP-binpac.h"

DHCP_Analyzer_binpac::DHCP_Analyzer_binpac(Connection* conn)
: Analyzer(AnalyzerTag::DHCP_BINPAC, conn)
	{
	interp = new binpac::DHCP::DHCP_Conn(this);
	}

DHCP_Analyzer_binpac::~DHCP_Analyzer_binpac()
	{
	delete interp;
	}

void DHCP_Analyzer_binpac::Done()
	{
	Analyzer::Done();
	}

void DHCP_Analyzer_binpac::DeliverPacket(int len, const u_char* data,
			bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}
