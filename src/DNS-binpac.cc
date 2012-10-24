#include "DNS-binpac.h"
#include "TCP_Reassembler.h"

DNS_UDP_Analyzer_binpac::DNS_UDP_Analyzer_binpac(Connection* conn)
: Analyzer(AnalyzerTag::DNS_UDP_BINPAC, conn)
	{
	interp = new binpac::DNS::DNS_Conn(this);
	did_session_done = 0;
	ADD_ANALYZER_TIMER(&DNS_UDP_Analyzer_binpac::ExpireTimer,
			network_time + dns_session_timeout, 1, TIMER_DNS_EXPIRE);
	}

DNS_UDP_Analyzer_binpac::~DNS_UDP_Analyzer_binpac()
	{
	delete interp;
	}

void DNS_UDP_Analyzer_binpac::Done()
	{
	Analyzer::Done();

	if ( ! did_session_done )
		Event(udp_session_done);
	}

void DNS_UDP_Analyzer_binpac::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}

void DNS_UDP_Analyzer_binpac::ExpireTimer(double t)
	{
	// The - 1.0 in the following is to allow 1 second for the
	// common case of a single request followed by a single reply,
	// so we don't needlessly set the timer twice in that case.
	if ( t - Conn()->LastTime() >= dns_session_timeout - 1.0 || terminating )
		{
		Event(connection_timeout);
		sessions->Remove(Conn());
		}
	else
		ADD_ANALYZER_TIMER(&DNS_UDP_Analyzer_binpac::ExpireTimer,
				t + dns_session_timeout, 1, TIMER_DNS_EXPIRE);
	}

DNS_TCP_Analyzer_binpac::DNS_TCP_Analyzer_binpac(Connection* conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::DNS_TCP_BINPAC, conn)
	{
	interp = new binpac::DNS_on_TCP::DNS_TCP_Conn(this);
	}

DNS_TCP_Analyzer_binpac::~DNS_TCP_Analyzer_binpac()
	{
	delete interp;
	}

void DNS_TCP_Analyzer_binpac::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void DNS_TCP_Analyzer_binpac::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void DNS_TCP_Analyzer_binpac::DeliverStream(int len, const u_char* data,
						bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() || TCP()->HadGap(orig) )
		// punt-on-partial or stop-on-gap.
		return;

	interp->NewData(orig, data, data + len);
	}

void DNS_TCP_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
