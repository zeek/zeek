// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/modbus/Modbus.h"

#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::modbus {

namespace {

// Offset of the first plausible Modbus/TCP ADU in d: protocol id 0, a length
// the MBAP allows (2..254) and a nonzero function code, followed by another
// plausible MBAP header where the announced ADU ends. Modbus has no start
// marker, so this is a heuristic; checking the next header keeps the tail of a
// request cut by the gap (for example 01 03 00 00 00 0a, a read of 10
// registers at address 0) from being taken as a header. Returns -1 if there is
// no candidate. Sets need_more if the first candidate's next header is not in
// d yet; the caller then waits for more data.
int ResyncOffset(const u_char* d, int len, bool& need_more) {
    auto plausible = [d, len](int i) {
        int l = (d[i + 4] << 8) | d[i + 5];
        return d[i + 2] == 0 && d[i + 3] == 0 && l >= 2 && l <= 254 && (d[i + 7] & 0x7f) != 0;
    };

    need_more = false;

    for ( int i = 0; i + 8 <= len; ++i ) {
        if ( ! plausible(i) )
            continue;
        int next = i + 6 + ((d[i + 4] << 8) | d[i + 5]);
        if ( next + 8 > len ) {
            need_more = true;
            return i;
        }
        if ( plausible(next) )
            return i;
    }

    return -1;
}

} // namespace

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

    if ( resync[orig] ) {
        std::string& p = pending[orig];
        p.append(reinterpret_cast<const char*>(data), len);
        bool need_more = false;
        int i = ResyncOffset(reinterpret_cast<const u_char*>(p.data()), static_cast<int>(p.size()), need_more);
        if ( i < 0 ) {
            if ( p.size() > 7 ) // keep what may still begin a header
                p.erase(0, p.size() - 7);
            return;
        }

        if ( need_more ) { // wait until the header after the candidate arrives
            p.erase(0, i);
            return;
        }

        resync[orig] = false; // back in sync
        std::string from(p, i);
        p.clear();
        const auto* b = reinterpret_cast<const u_char*>(from.data());
        interp->NewData(orig, b, b + from.size());
        return;
    }

    interp->NewData(orig, data, data + len);
}

void ModbusTCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    interp->NewGap(orig, len);

    // The PDU being parsed cannot be completed: drop it and resynchronize.
    // Without this its remaining fields are taken from the data after the gap,
    // and the flow stays misaligned, waiting for lengths read from the middle
    // of later ADUs, without a weird or a violation.
    (orig ? interp->upflow() : interp->downflow())->discard_pdu();
    resync[orig] = true;
    pending[orig].clear();
    Weird("modbus_gap_resync");
}

void ModbusTCP_Analyzer::EndpointEOF(bool is_orig) {
    TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
}

} // namespace zeek::analyzer::modbus
