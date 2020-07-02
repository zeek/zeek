#pragma once

#include "ayiya_pac.h"

namespace analyzer { namespace ayiya {

class AYIYA_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit AYIYA_Analyzer(Connection* conn);
	virtual ~AYIYA_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen);

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new AYIYA_Analyzer(conn); }

protected:
	binpac::AYIYA::AYIYA_Conn* interp;
};

} } // namespace analyzer::*
