// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_SNMP_SNMP_H
#define ANALYZER_PROTOCOL_SNMP_SNMP_H

#include "snmp_pac.h"

namespace analyzer { namespace snmp {

class SNMP_Analyzer : public analyzer::Analyzer {

public:

	explicit SNMP_Analyzer(Connection* conn);
	virtual ~SNMP_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(uint64_t len, const u_char* data, bool orig,
	                           uint64_t seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SNMP_Analyzer(conn); }

protected:

	binpac::SNMP::SNMP_Conn* interp;
};

} } // namespace analyzer::*

#endif
