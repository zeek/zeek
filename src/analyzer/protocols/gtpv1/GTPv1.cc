// See the file "COPYING" in the main distribution directory for copyright.

#include "GTPv1.h"

#include "events.bif.h"

using namespace analyzer::gtpv1;

GTPv1_Analyzer::GTPv1_Analyzer(Connection* conn)
: Analyzer("GTPV1", conn)
	{
	interp = new binpac::GTPv1::GTPv1_Conn(this);
	}

GTPv1_Analyzer::~GTPv1_Analyzer()
	{
	delete interp;
	}

void GTPv1_Analyzer::Done()
	{
	Analyzer::Done();
	Event(udp_session_done);
	}

void GTPv1_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
