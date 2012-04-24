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

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new AYIYA_Analyzer(conn); }

	static bool Available()
		{ return BifConst::Tunnel::decapsulate_ip; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);

	int did_session_done;

	binpac::AYIYA::AYIYA_Conn* interp;
};

#endif
