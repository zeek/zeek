#pragma once

#include "analyzer/protocol/ayiya/ayiya_pac.h"

namespace binpac::AYIYA { class AYIYA_Conn; }

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

	void SetInnerInfo(int offset, uint8_t next)
		{
		inner_packet_offset = offset;
		next_header = next;
		}

protected:
	binpac::AYIYA::AYIYA_Conn* interp;
	int inner_packet_offset = -1;
	uint8_t next_header = 0;
};

} // namespace zeek::analyzer::ayiya
