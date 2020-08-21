#pragma once

#include "ayiya_pac.h"

namespace zeek::analyzer::ayiya {

class AYIYA_Analyzer final : public analyzer::Analyzer {
public:
	explicit AYIYA_Analyzer(Connection* conn);
	virtual ~AYIYA_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new AYIYA_Analyzer(conn); }

protected:
	binpac::AYIYA::AYIYA_Conn* interp;
};

} // namespace zeek::analyzer::ayiya

namespace analyzer::ayiya {

using AYIYA_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::ayiya::AYIYA_Analyzer.")]] = zeek::analyzer::ayiya::AYIYA_Analyzer;

} // namespace analyzer::ayiya
