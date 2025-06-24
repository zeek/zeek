// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/protocol/snmp/snmp_pac.h"

namespace zeek::analyzer::snmp {

class SNMP_Analyzer final : public analyzer::Analyzer {
public:
    explicit SNMP_Analyzer(Connection* conn);
    ~SNMP_Analyzer() override;

    void Done() override;
    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;

    static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn) { return new SNMP_Analyzer(conn); }

protected:
    binpac::SNMP::SNMP_Conn* interp;
};

} // namespace zeek::analyzer::snmp
