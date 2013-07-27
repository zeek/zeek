#ifndef ANALYZER_PROTOCOL_AYIYA_AYIYA_H
#define ANALYZER_PROTOCOL_AYIYA_AYIYA_H

#include "ayiya_pac.h"

namespace analyzer { namespace ayiya {

class AYIYA_Analyzer : public analyzer::Analyzer {
public:
	AYIYA_Analyzer(Connection* conn);
	virtual ~AYIYA_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new AYIYA_Analyzer(conn); }

protected:
	void ExpireTimer(double t);

	binpac::AYIYA::AYIYA_Conn* interp;
};

} } // namespace analyzer::* 

#endif
