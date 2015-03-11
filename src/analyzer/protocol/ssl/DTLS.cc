
#include "DTLS.h"
#include "Reporter.h"
#include "util.h"

#include "events.bif.h"

using namespace analyzer::dtls;

DTLS_Analyzer::DTLS_Analyzer(Connection* c)
: analyzer::Analyzer("DTLS", c)
	{
	interp = new binpac::DTLS::SSL_Conn(this);
	fprintf(stderr, "Instantiated :)\n");
	}

DTLS_Analyzer::~DTLS_Analyzer()
	{
	delete interp;
	}

void DTLS_Analyzer::Done()
	{
		Analyzer::Done();
	}

void DTLS_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	fprintf(stderr, "Delivered packet :)\n");
	interp->NewData(orig, data, data + len);
	}
