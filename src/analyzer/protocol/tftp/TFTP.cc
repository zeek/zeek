
#include "TFTP.h"
#include "events.bif.h"

using namespace analyzer::tftp;

TFTP_Analyzer::TFTP_Analyzer(Connection* conn)
: Analyzer("TFTP", conn)
	{
	interp = new binpac::TFTP::TFTP_Conn(this);
	did_session_done = 0;
	}

TFTP_Analyzer::~TFTP_Analyzer()
	{
	delete interp;
	}

void TFTP_Analyzer::Done()
	{
	Analyzer::Done();

	if ( ! did_session_done )
		Event(udp_session_done);
	}

void TFTP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}
