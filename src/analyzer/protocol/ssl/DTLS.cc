
#include "DTLS.h"
#include "Reporter.h"
#include "util.h"

#include "events.bif.h"

#include "dtls_pac.h"
#include "tls-handshake_pac.h"

using namespace analyzer::dtls;

DTLS_Analyzer::DTLS_Analyzer(Connection* c)
: analyzer::Analyzer("DTLS", c)
	{
	interp = new binpac::DTLS::SSL_Conn(this);
	handshake_interp = new binpac::TLSHandshake::Handshake_Conn(this);
	}

DTLS_Analyzer::~DTLS_Analyzer()
	{
	delete interp;
	delete handshake_interp;
	}

void DTLS_Analyzer::Done()
	{
	Analyzer::Done();
	interp->FlowEOF(true);
	interp->FlowEOF(false);
	handshake_interp->FlowEOF(true);
	handshake_interp->FlowEOF(false);
	}

void DTLS_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}

void DTLS_Analyzer::EndOfData(bool is_orig)
	{
	Analyzer::EndOfData(is_orig);
	interp->FlowEOF(is_orig);
	handshake_interp->FlowEOF(is_orig);
	}


void DTLS_Analyzer::SendHandshake(uint8 msg_type, uint32 length, const u_char* begin, const u_char* end, bool orig)
	{
	try
		{
		handshake_interp->NewData(orig, (const unsigned char*) &msg_type, (const unsigned char*) &msg_type + 1);
		uint32 host_length = htonl(length);
		// the parser inspects a uint24 - since it is big-endian, it should be ok to just skip
		// the first byte of the uint32. Since we get the data from an uint24 from the dtls-parser, this should
		// always yield the correct result.
		handshake_interp->NewData(orig, (const unsigned char*) &host_length + 1, (const unsigned char*) &host_length + sizeof(host_length));
		handshake_interp->NewData(orig, begin, end);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
