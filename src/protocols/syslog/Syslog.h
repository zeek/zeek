
#ifndef Syslog_h
#define Syslog_h

#include "UDP.h"
#include "TCP.h"

#include "syslog_pac.h"

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
//class Syslog_TCP_Analyzer : public TCP_ApplicationAnalyzer {
//public:
//	Syslog_TCP_Analyzer(Connection* conn);
//	virtual ~Syslog_TCP_Analyzer();
//
//	virtual void Done();
//	virtual void DeliverStream(int len, const u_char* data, bool orig);
//	virtual void Undelivered(int seq, int len, bool orig);
//	virtual void EndpointEOF(TCP_Reassembler* endp);
//
//	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
//		{ return new Syslog_TCP_Analyzer(conn); }
//
//protected:
//	binpac::Syslog_on_TCP::Syslog_TCP_Conn* interp;
//};
//
#endif
