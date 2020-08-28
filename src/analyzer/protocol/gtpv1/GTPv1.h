#pragma once

#include "gtpv1_pac.h"

namespace binpac::GTPv1 { class GTPv1_Conn; }

namespace analyzer { namespace gtpv1 {

class GTPv1_Analyzer final : public analyzer::Analyzer {
public:
	explicit GTPv1_Analyzer(Connection* conn);
	virtual ~GTPv1_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new GTPv1_Analyzer(conn); }

	void SetInnerInfo(int offset, uint8_t next, zeek::RecordValPtr val)
		{
		inner_packet_offset = offset;
		next_header = next;
		gtp_hdr_val = std::move(val);
		}

protected:
	binpac::GTPv1::GTPv1_Conn* interp;
	int inner_packet_offset = -1;
	uint8_t next_header = 0;
	zeek::RecordValPtr gtp_hdr_val;
};

} } // namespace analyzer::*
