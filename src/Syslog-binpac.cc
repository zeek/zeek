#include "Syslog-binpac.h"
#include "TCP_Reassembler.h"

Syslog_Analyzer_binpac::Syslog_Analyzer_binpac(Connection* conn)
: Analyzer(AnalyzerTag::SYSLOG_BINPAC, conn)
	{
	interp = new binpac::Syslog::Syslog_Conn(this);
	did_session_done = 0;
	//ADD_ANALYZER_TIMER(&Syslog_Analyzer_binpac::ExpireTimer,
	//		network_time + Syslog_session_timeout, 1, TIMER_Syslog_EXPIRE);
	}

Syslog_Analyzer_binpac::~Syslog_Analyzer_binpac()
	{
	delete interp;
	}

void Syslog_Analyzer_binpac::Done()
	{
	Analyzer::Done();

	if ( ! did_session_done )
		Event(udp_session_done);
	}

void Syslog_Analyzer_binpac::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}

//void Syslog_Analyzer_binpac::ExpireTimer(double t)
//	{
//	// The - 1.0 in the following is to allow 1 second for the
//	// common case of a single request followed by a single reply,
//	// so we don't needlessly set the timer twice in that case.
//	if ( t - Conn()->LastTime() >= Syslog_session_timeout - 1.0 || terminating )
//		{
//		Event(connection_timeout);
//		sessions->Remove(Conn());
//		}
//	else
//		ADD_ANALYZER_TIMER(&Syslog_Analyzer_binpac::ExpireTimer,
//				t + Syslog_session_timeout, 1, TIMER_Syslog_EXPIRE);
//	}

//Syslog_TCP_Analyzer_binpac::Syslog_TCP_Analyzer_binpac(Connection* conn)
//: TCP_ApplicationAnalyzer(AnalyzerTag::Syslog_TCP_BINPAC, conn)
//	{
//	interp = new binpac::Syslog_on_TCP::Syslog_TCP_Conn(this);
//	}

//Syslog_TCP_Analyzer_binpac::~Syslog_TCP_Analyzer_binpac()
//	{
//	delete interp;
//	}

//void Syslog_TCP_Analyzer_binpac::Done()
//	{
//	TCP_ApplicationAnalyzer::Done();
//
//	interp->FlowEOF(true);
//	interp->FlowEOF(false);
//	}

//void Syslog_TCP_Analyzer_binpac::EndpointEOF(TCP_Reassembler* endp)
//	{
//	TCP_ApplicationAnalyzer::EndpointEOF(endp);
//	interp->FlowEOF(endp->IsOrig());
//	}

//void Syslog_TCP_Analyzer_binpac::DeliverStream(int len, const u_char* data,
//						bool orig)
//	{
//	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
//
//	assert(TCP());
//
//	if ( TCP()->IsPartial() || TCP()->HadGap(orig) )
//		// punt-on-partial or stop-on-gap.
//		return;
//
//	interp->NewData(orig, data, data + len);
//	}

//void Syslog_TCP_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
//	{
//	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
//	interp->NewGap(orig, len);
//	}
