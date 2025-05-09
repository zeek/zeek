// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/modbus/Modbus.h"

#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::modbus {

ModbusTCP_Analyzer::ModbusTCP_Analyzer(Connection* c) : TCP_ApplicationAnalyzer("MODBUS", c) {
    interp = new binpac::ModbusTCP::ModbusTCP_Conn(this);
}

ModbusTCP_Analyzer::~ModbusTCP_Analyzer() { delete interp; }

void ModbusTCP_Analyzer::Done() {
    TCP_ApplicationAnalyzer::Done();

    interp->FlowEOF(true);
    interp->FlowEOF(false);
}

void ModbusTCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
    interp->NewData(orig, data, data + len);
}

void ModbusTCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    interp->NewGap(orig, len);
}

void ModbusTCP_Analyzer::EndpointEOF(bool is_orig) {
    TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
}

} // namespace zeek::analyzer::modbus
