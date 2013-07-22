
#ifndef ANALYZER_PROTOCOL_SYSLOG_SYSLOG_H
#define ANALYZER_PROTOCOL_SYSLOG_SYSLOG_H

#include "analyzer/protocol/udp/UDP.h"
#include "analyzer/protocol/tcp/TCP.h"

#include "syslog_pac.h"

namespace analyzer { namespace syslog {

class Syslog_Analyzer : public analyzer::Analyzer {
public:
	Syslog_Analyzer(Connection* conn);
	virtual ~Syslog_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Syslog_Analyzer(conn); }

protected:
	void ExpireTimer(double t);

	int did_session_done;

	binpac::Syslog::Syslog_Conn* interp;
};

// #include "Syslog_tcp_pac.h"
//
//class Syslog_tcp::TCP_Analyzer : public tcp::TCP_ApplicationAnalyzer {
//public:
//	Syslog_tcp::TCP_Analyzer(Connection* conn);
//	virtual ~Syslog_tcp::TCP_Analyzer();
//
//	virtual void Done();
//	virtual void DeliverStream(int len, const u_char* data, bool orig);
//	virtual void Undelivered(int seq, int len, bool orig);
//	virtual void EndpointEOF(tcp::TCP_Reassembler* endp);
//
//	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
//		{ return new Syslog_tcp::TCP_Analyzer(conn); }
//
//protected:
//	binpac::Syslog_on_TCP::Syslog_TCP_Conn* interp;
//};
//
} } // namespace analyzer::* 

#endif
