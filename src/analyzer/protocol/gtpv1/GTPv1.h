#pragma once

#include "gtpv1_pac.h"

namespace analyzer { namespace gtpv1 {

class GTPv1_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit GTPv1_Analyzer(Connection* conn);
	virtual ~GTPv1_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen);

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new GTPv1_Analyzer(conn); }

protected:
	binpac::GTPv1::GTPv1_Conn* interp;
};

} } // namespace analyzer::*
