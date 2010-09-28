// $Id:$

#ifndef dhcp_binpac_h
#define dhcp_binpac_h

#include "UDP.h"

#include "dhcp_pac.h"


class DHCP_Analyzer_binpac : public Analyzer {
public:
	DHCP_Analyzer_binpac(Connection* conn);
	virtual ~DHCP_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DHCP_Analyzer_binpac(conn); }

	static bool Available()
		{ return dhcp_request && FLAGS_use_binpac; }

protected:
	binpac::DHCP::DHCP_Conn* interp;
};

#endif
