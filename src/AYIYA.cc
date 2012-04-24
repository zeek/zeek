#include "AYIYA.h"

AYIYA_Analyzer::AYIYA_Analyzer(Connection* conn)
: Analyzer(AnalyzerTag::SYSLOG_BINPAC, conn)
	{
	interp = new binpac::AYIYA::AYIYA_Conn(this);
	did_session_done = 0;
	}

AYIYA_Analyzer::~AYIYA_Analyzer()
	{
	delete interp;
	}

void AYIYA_Analyzer::Done()
	{
	Analyzer::Done();

	if ( ! did_session_done )
		Event(udp_session_done);
	}

void AYIYA_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}
