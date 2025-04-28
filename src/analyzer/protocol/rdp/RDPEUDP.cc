// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/rdp/RDPEUDP.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/rdp/rdpeudp_pac.h"

namespace zeek::analyzer::rdpeudp {

RDP_Analyzer::RDP_Analyzer(Connection* c) : analyzer::Analyzer("RDPEUDP", c) {
    interp = new binpac::RDPEUDP::RDPEUDP_Conn(this);
}

RDP_Analyzer::~RDP_Analyzer() { delete interp; }

void RDP_Analyzer::Done() { Analyzer::Done(); }

void RDP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    try {
        interp->NewData(orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
    }
}

} // namespace zeek::analyzer::rdpeudp
