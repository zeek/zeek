#pragma once

#include "events.bif.h"


#include "analyzer/protocol/udp/UDP.h"
#include "analyzer/protocol/pia/PIA.h"

#include "rdpeudp_pac.h"

namespace analyzer { namespace rdpeudp {

class RDPEUDP_Analyzer : public analyzer::Analyzer {

public:
	explicit RDPEUDP_Analyzer(Connection* conn);
	~RDPEUDP_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen) override;
	void EndOfData(bool is_orig) override;
	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new RDPEUDP_Analyzer(conn); }

protected:
	binpac::RDPEUDP::RDPEUDP_Conn* interp;
};

} } // namespace analyzer::* 
