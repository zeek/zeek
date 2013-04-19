#ifndef ANALYZER_PROTOCOL_GTPV1_GTPV1_H
#define ANALYZER_PROTOCOL_GTPV1_GTPV1_H

#include "gtpv1_pac.h"

namespace analyzer { namespace gtpv1 {

class GTPv1_Analyzer : public analyzer::Analyzer {
public:
	GTPv1_Analyzer(Connection* conn);
	virtual ~GTPv1_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new GTPv1_Analyzer(conn); }

protected:
	void ExpireTimer(double t);

	binpac::GTPv1::GTPv1_Conn* interp;
};

} } // namespace analyzer::* 

#endif
