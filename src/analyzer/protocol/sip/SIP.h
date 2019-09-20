#ifndef ANALYZER_PROTOCOL_SIP_SIP_H
#define ANALYZER_PROTOCOL_SIP_SIP_H

#include "events.bif.h"

#include "analyzer/protocol/udp/UDP.h"
#include "sip_pac.h"

namespace analyzer { namespace SIP {

class SIP_Analyzer : public analyzer::Analyzer {
public:
	explicit SIP_Analyzer(Connection* conn);
	~SIP_Analyzer() override;

	// Overridden from Analyzer

	void Done() override;
	void DeliverPacket(uint64_t len, const u_char* data, bool orig,
				   	   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
	{ return new SIP_Analyzer(conn); }

protected:
	binpac::SIP::SIP_Conn* interp;
};

} } // namespace analyzer::*

#endif
