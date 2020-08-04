// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "snmp_pac.h"

namespace zeek::analyzer::snmp {

class SNMP_Analyzer final : public zeek::analyzer::Analyzer {

public:

	explicit SNMP_Analyzer(zeek::Connection* conn);
	virtual ~SNMP_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
	                           uint64_t seq, const zeek::IP_Hdr* ip, int caplen);

	static zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
		{ return new SNMP_Analyzer(conn); }

protected:

	binpac::SNMP::SNMP_Conn* interp;
};

} // namespace zeek::analyzer::snmp

namespace analyzer::snmp {

using SNMP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::snmp::SNMP_Analyzer.")]] = zeek::analyzer::snmp::SNMP_Analyzer;

} // namespace analyzer::snmp
