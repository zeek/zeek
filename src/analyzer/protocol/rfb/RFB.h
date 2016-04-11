#ifndef ANALYZER_PROTOCOL_RFB_RFB_H
#define ANALYZER_PROTOCOL_RFB_RFB_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "rfb_pac.h"

namespace analyzer { namespace rfb {

class RFB_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	RFB_Analyzer(Connection* conn);
	virtual ~RFB_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);


	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new RFB_Analyzer(conn); }

protected:
	binpac::RFB::RFB_Conn* interp;

	bool had_gap;

};

} } // namespace analyzer::*

#endif
