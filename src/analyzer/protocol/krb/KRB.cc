// See the file "COPYING" in the main distribution directory for copyright.

#include "KRB.h"
#include "types.bif.h"
#include "events.bif.h"

using namespace analyzer::krb;

KRB_Analyzer::KRB_Analyzer(Connection* conn)
	: Analyzer("KRB", conn)
	{
	interp = new binpac::KRB::KRB_Conn(this);
	}

KRB_Analyzer::~KRB_Analyzer()
	{
	delete interp;
	}

void KRB_Analyzer::Done()
	{
	Analyzer::Done();
	}

void KRB_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
				 uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(e.c_msg());
		}
	}

