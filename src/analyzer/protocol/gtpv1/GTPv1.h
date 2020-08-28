#ifndef ANALYZER_PROTOCOL_GTPV1_GTPV1_H
#define ANALYZER_PROTOCOL_GTPV1_GTPV1_H

#include "gtpv1_pac.h"

namespace binpac::GTPv1 { class GTPv1_Conn; }

namespace analyzer { namespace gtpv1 {

class GTPv1_Analyzer : public analyzer::Analyzer {
public:
	explicit GTPv1_Analyzer(Connection* conn);
	virtual ~GTPv1_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new GTPv1_Analyzer(conn); }

	void SetInnerInfo(int offset, uint8_t next, RecordVal* val)
		{
		inner_packet_offset = offset;
		next_header = next;
		gtp_hdr_val = val;
		}

protected:
	binpac::GTPv1::GTPv1_Conn* interp;
	int inner_packet_offset = -1;
	uint8_t next_header = 0;
	RecordVal* gtp_hdr_val;
};

} } // namespace analyzer::* 

#endif
