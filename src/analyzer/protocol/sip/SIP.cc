// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/sip/SIP.h"

namespace zeek::analyzer::sip {

SIP_Analyzer::SIP_Analyzer(Connection* c) : analyzer::Analyzer("SIP", c) { interp = new binpac::SIP::SIP_Conn(this); }

SIP_Analyzer::~SIP_Analyzer() { delete interp; }

void SIP_Analyzer::Done() { Analyzer::Done(); }

void SIP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    bool real_orig = true;
    if ( len > 6 && data[0] == 'S' && data[1] == 'I' && data[2] == 'P' && data[3] == '/' )
        real_orig = false;

    // Sometimes we see some packets with just '\r\n' - ignore those
    if ( len == 2 && data[0] == '\r' )
        return;

    Analyzer::DeliverPacket(len, data, real_orig, seq, ip, caplen);

    try {
        interp->NewData(real_orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
    }
}

} // namespace zeek::analyzer::sip
