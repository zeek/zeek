#ifndef dhcp_binpac_h
#define dhcp_binpac_h

#include "analyzer/protocols/udp/UDP.h"

#include "dhcp_pac.h"

namespace analyzer { namespace dhcp {

class DHCP_Analyzer : public analyzer::Analyzer {
public:
	DHCP_Analyzer(Connection* conn);
	virtual ~DHCP_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DHCP_Analyzer(conn); }

protected:
	binpac::DHCP::DHCP_Conn* interp;
};

} } // namespace analyzer::* 

#endif
