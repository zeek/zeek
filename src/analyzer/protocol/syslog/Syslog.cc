#include "zeek/analyzer/protocol/syslog/Syslog.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

#include "zeek/analyzer/protocol/syslog/events.bif.h"

namespace zeek::analyzer::syslog {

Syslog_Analyzer::Syslog_Analyzer(Connection* conn)
: Analyzer("SYSLOG", conn)
	{
	interp = new binpac::Syslog::Syslog_Conn(this);
	did_session_done = 0;
	//ADD_ANALYZER_TIMER(&Syslog_Analyzer::ExpireTimer,
	//		network_time + Syslog_session_timeout, true, TIMER_Syslog_EXPIRE);
	}

Syslog_Analyzer::~Syslog_Analyzer()
	{
	delete interp;
	}

void Syslog_Analyzer::Done()
	{
	Analyzer::Done();

	if ( ! did_session_done )
		Event(udp_session_done);
	}

void Syslog_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}

//void Syslog_Analyzer::ExpireTimer(double t)
//	{
//	// The - 1.0 in the following is to allow 1 second for the
//	// common case of a single request followed by a single reply,
//	// so we don't needlessly set the timer twice in that case.
//	if ( t - Conn()->LastTime() >= Syslog_session_timeout - 1.0 || terminating )
//		{
//		Event(connection_timeout);
//		session_mgr->Remove(Conn());
//		}
//	else
//		ADD_ANALYZER_TIMER(&Syslog_Analyzer::ExpireTimer,
//				t + Syslog_session_timeout, true, TIMER_Syslog_EXPIRE);
//	}

//Syslog_tcp::TCP_Analyzer::Syslog_tcp::TCP_Analyzer(Connection* conn)
//: analyzer::tcp::TCP_ApplicationAnalyzer(conn)
//	{
//	interp = new binpac::Syslog_on_TCP::Syslog_TCP_Conn(this);
//	}

//Syslog_tcp::TCP_Analyzer::~Syslog_tcp::TCP_Analyzer()
//	{
//	delete interp;
//	}

//void Syslog_tcp::TCP_Analyzer::Done()
//	{
//	analyzer::tcp::TCP_ApplicationAnalyzer::Done();
//
//	interp->FlowEOF(true);
//	interp->FlowEOF(false);
//	}

//void Syslog_tcp::TCP_Analyzer::EndpointEOF(tcp::TCP_Reassembler* endp)
//	{
//	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(endp);
//	interp->FlowEOF(endp->IsOrig());
//	}

//void Syslog_tcp::TCP_Analyzer::DeliverStream(int len, const u_char* data,
//						bool orig)
//	{
//	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
//
//	assert(TCP());
//
//	if ( TCP()->IsPartial() || TCP()->HadGap(orig) )
//		// punt-on-partial or stop-on-gap.
//		return;
//
//	interp->NewData(orig, data, data + len);
//	}

//void Syslog_tcp::TCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
//	{
//	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
//	interp->NewGap(orig, len);
//	}

} // namespace zeek::analyzer::syslog
