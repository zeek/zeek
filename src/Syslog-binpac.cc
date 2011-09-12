#include "Syslog-binpac.h"
#include "TCP_Reassembler.h"

Syslog_UDP_Analyzer_binpac::Syslog_UDP_Analyzer_binpac(Connection* conn)
: Analyzer(AnalyzerTag::SYSLOG, conn)
	{
	interp = new binpac::Syslog::Syslog_Conn(this);
	}

Syslog_UDP_Analyzer_binpac::~Syslog_UDP_Analyzer_binpac()
	{
	delete interp;
	}

void Syslog_UDP_Analyzer_binpac::Done()
	{
	Analyzer::Done();
	
	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void Syslog_UDP_Analyzer_binpac::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	interp->NewData(orig, data, data + len);
	}


Syslog_TCP_Analyzer_binpac::Syslog_TCP_Analyzer_binpac(Connection* conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::SYSLOG_TCP, conn)
	{
	interp = new binpac::Syslog_TCP::Syslog_TCP_Conn(this);
	}

Syslog_TCP_Analyzer_binpac::~Syslog_TCP_Analyzer_binpac()
	{
	delete interp;
	}

void Syslog_TCP_Analyzer_binpac::Done()
	{
	TCP_ApplicationAnalyzer::Done();
	
	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void Syslog_TCP_Analyzer_binpac::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}

void Syslog_TCP_Analyzer_binpac::DeliverStream(int len, const u_char* data,
						bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	// TODO: We could probably resync with syslog traffic pretty easily.
	if ( TCP()->IsPartial() || TCP()->HadGap(orig) )
		// punt-on-partial or stop-on-gap.
		return;

	interp->NewData(orig, data, data + len);
	}

void Syslog_TCP_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
