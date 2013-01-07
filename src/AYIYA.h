#ifndef AYIYA_h
#define AYIYA_h

#include "ayiya_pac.h"

class AYIYA_Analyzer : public Analyzer {
public:
	AYIYA_Analyzer(Connection* conn);
	virtual ~AYIYA_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn, const AnalyzerTag& tag)
		{ return new AYIYA_Analyzer(conn); }

	static bool Available(const AnalyzerTag& tag)
		{ return BifConst::Tunnel::enable_ayiya &&
		         BifConst::Tunnel::max_depth > 0; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);

	binpac::AYIYA::AYIYA_Conn* interp;
};

#endif
