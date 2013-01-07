#ifndef GTPv1_h
#define GTPv1_h

#include "gtpv1_pac.h"

class GTPv1_Analyzer : public Analyzer {
public:
	GTPv1_Analyzer(Connection* conn);
	virtual ~GTPv1_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn, const AnalyzerTag& tag)
		{ return new GTPv1_Analyzer(conn); }

	static bool Available(const AnalyzerTag& tag)
		{ return BifConst::Tunnel::enable_gtpv1 &&
		         BifConst::Tunnel::max_depth > 0; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);

	binpac::GTPv1::GTPv1_Conn* interp;
};

#endif
