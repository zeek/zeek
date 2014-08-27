#ifndef ANALYZER_PROTOCOL_SIP_SIP_H
#define ANALYZER_PROTOCOL_SIP_SIP_H

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"
#include "sip_pac.h"

namespace analyzer { namespace sip {

class SIP_Analyzer : public analyzer::Analyzer {
public:
	SIP_Analyzer(Connection* conn);
	virtual ~SIP_Analyzer();

	// Overridden from Analyzer

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
				   			   uint64 seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
	{ return new SIP_Analyzer(conn); }

	static bool Available()
	{ return sip_request || sip_reply || sip_header ||
		     sip_all_headers || sip_begin_entity || sip_end_entity; }

protected:
	binpac::SIP::SIP_Conn* interp;
};

} } // namespace analyzer::* 

#endif
