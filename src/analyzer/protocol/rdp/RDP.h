#ifndef ANALYZER_PROTOCOL_RDP_RDP_H
#define ANALYZER_PROTOCOL_RDP_RDP_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"

#include "rdp_pac.h"

namespace analyzer { namespace rdp {

class RDP_Analyzer : public tcp::TCP_ApplicationAnalyzer {

public:
	RDP_Analyzer(Connection* conn);
	virtual ~RDP_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new RDP_Analyzer(conn); }

protected:
	binpac::RDP::RDP_Conn* interp;
	
	bool had_gap;
	pia::PIA_TCP *pia;
};

} } // namespace analyzer::* 

#endif
