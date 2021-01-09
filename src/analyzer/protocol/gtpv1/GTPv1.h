#pragma once

#include "analyzer/protocol/gtpv1/gtpv1_pac.h"

namespace binpac::GTPv1
{
class GTPv1_Conn;
}

namespace zeek::analyzer::gtpv1
{

class GTPv1_Analyzer final : public analyzer::Analyzer
	{
public:
	explicit GTPv1_Analyzer(Connection* conn);
	virtual ~GTPv1_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
	                           const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new GTPv1_Analyzer(conn); }

	void SetInnerInfo(int offset, uint8_t next, RecordValPtr val)
		{
		inner_packet_offset = offset;
		next_header = next;
		gtp_hdr_val = std::move(val);
		}

protected:
	binpac::GTPv1::GTPv1_Conn* interp;
	int inner_packet_offset = -1;
	uint8_t next_header = 0;
	RecordValPtr gtp_hdr_val;
	};

} // namespace zeek::analyzer::gtpv1

namespace analyzer::gtpv1
{

using GTPv1_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::gtpv1::GTPv1_Analyzer.")]] =
	zeek::analyzer::gtpv1::GTPv1_Analyzer;

} // namespace analyzer::gtpv1
