
#ifndef ANALYZER_PROTOCOL_TFTP_TFTP_H
#define ANALYZER_PROTOCOL_TFTP_TFTP_H

#include "analyzer/protocol/udp/UDP.h"
#include "tftp_pac.h"

namespace analyzer { namespace tftp {

class TFTP_Analyzer : public analyzer::Analyzer {
public:
	TFTP_Analyzer(Connection* conn);
	virtual ~TFTP_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new TFTP_Analyzer(conn); }

protected:
	void ExpireTimer(double t);

	int did_session_done;

	binpac::TFTP::TFTP_Conn* interp;
};

} } // namespace analyzer::* 

#endif
