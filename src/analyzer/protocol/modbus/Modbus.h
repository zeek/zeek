// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/modbus/modbus_pac.h"

namespace zeek::analyzer::modbus {

class ModbusTCP_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit ModbusTCP_Analyzer(Connection* conn);
    ~ModbusTCP_Analyzer() override;

    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;

    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndpointEOF(bool is_orig) override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new ModbusTCP_Analyzer(conn); }

protected:
    binpac::ModbusTCP::ModbusTCP_Conn* interp;

    // After a TCP gap, per direction (index: orig): skip to the next
    // plausible MBAP header, buffering the octets that may still begin one.
    bool resync[2] = {false, false};
    std::string pending[2];
};

} // namespace zeek::analyzer::modbus
