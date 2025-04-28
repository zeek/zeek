// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/ssl/DTLS.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/ssl/dtls_pac.h"
#include "zeek/analyzer/protocol/ssl/tls-handshake_pac.h"
#include "zeek/util.h"

namespace zeek::analyzer::dtls {

DTLS_Analyzer::DTLS_Analyzer(Connection* c) : analyzer::Analyzer("DTLS", c) {
    interp = new binpac::DTLS::SSL_Conn(this);
    handshake_interp = new binpac::TLSHandshake::Handshake_Conn(this);
}

DTLS_Analyzer::~DTLS_Analyzer() {
    delete interp;
    delete handshake_interp;
}

void DTLS_Analyzer::Done() {
    Analyzer::Done();
    interp->FlowEOF(true);
    interp->FlowEOF(false);
    handshake_interp->FlowEOF(true);
    handshake_interp->FlowEOF(false);
}

void DTLS_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    // In this case the packet is a STUN packet. Skip it without complaining.
    if ( len > 20 && data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xa4 && data[7] == 0x42 )
        return;

    interp->NewData(orig, data, data + len);
}

void DTLS_Analyzer::EndOfData(bool is_orig) {
    Analyzer::EndOfData(is_orig);
    interp->FlowEOF(is_orig);
    handshake_interp->FlowEOF(is_orig);
}

uint16_t DTLS_Analyzer::GetNegotiatedVersion() const { return handshake_interp->chosen_version(); }

void DTLS_Analyzer::SendHandshake(uint16_t raw_tls_version, uint8_t msg_type, uint32_t length, const u_char* begin,
                                  const u_char* end, bool orig) {
    handshake_interp->set_record_version(raw_tls_version);
    try {
        handshake_interp->NewData(orig, (const unsigned char*)&msg_type, (const unsigned char*)&msg_type + 1);
        uint32_t host_length = htonl(length);
        // the parser inspects a uint24_t - since it is big-endian, it should be ok to just skip
        // the first byte of the uint32_t. Since we get the data from an uint24_t from the
        // dtls-parser, this should always yield the correct result.
        handshake_interp->NewData(orig, (const unsigned char*)&host_length + 1,
                                  (const unsigned char*)&host_length + sizeof(host_length));
        handshake_interp->NewData(orig, begin, end);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
    }
}

bool DTLS_Analyzer::TryDecryptApplicationData(int len, const u_char* data, bool is_orig, uint8_t content_type,
                                              uint16_t raw_tls_version) {
    // noop for now as DTLS decryption is currently not supported
    return false;
}

bool DTLS_Analyzer::GetFlipped() { return handshake_interp->flipped(); }

} // namespace zeek::analyzer::dtls
