#pragma once

#include "gtpv1_pac.h"

namespace zeek::analyzer::gtpv1 {

class GTPv1_Analyzer final : public zeek::analyzer::Analyzer {
public:
	explicit GTPv1_Analyzer(zeek::Connection* conn);
	virtual ~GTPv1_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const zeek::IP_Hdr* ip, int caplen);

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new GTPv1_Analyzer(conn); }

protected:
	binpac::GTPv1::GTPv1_Conn* interp;
};

} // namespace zeek::analyzer::gtpv1

namespace analyzer::gtpv1 {

	using GTPv1_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::gtpv1::GTPv1_Analyzer.")]] = zeek::analyzer::gtpv1::GTPv1_Analyzer;

} // namespace analyzer::gtpv1
