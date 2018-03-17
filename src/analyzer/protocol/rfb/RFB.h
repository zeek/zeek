#ifndef ANALYZER_PROTOCOL_RFB_RFB_H
#define ANALYZER_PROTOCOL_RFB_RFB_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "rfb_pac.h"

namespace analyzer { namespace rfb {

class RFB_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	explicit RFB_Analyzer(Connection* conn);
	~RFB_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;


	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new RFB_Analyzer(conn); }

protected:
	binpac::RFB::RFB_Conn* interp;

	bool had_gap;

};

} } // namespace analyzer::*

#endif
