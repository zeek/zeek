#ifndef Syslog_binpac_h
#define Syslog_binpac_h

#include "UDP.h"
#include "TCP.h"

#include "syslog_pac.h"

class Syslog_Analyzer_binpac : public Analyzer {
public:
	Syslog_Analyzer_binpac(Connection* conn);
	virtual ~Syslog_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Syslog_Analyzer_binpac(conn); }

	static bool Available()
		{ return syslog_message; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);

	int did_session_done;

	binpac::Syslog::Syslog_Conn* interp;
};

// #include "Syslog_tcp_pac.h"
//
//class Syslog_TCP_Analyzer_binpac : public TCP_ApplicationAnalyzer {
//public:
//	Syslog_TCP_Analyzer_binpac(Connection* conn);
//	virtual ~Syslog_TCP_Analyzer_binpac();
//
//	virtual void Done();
//	virtual void DeliverStream(int len, const u_char* data, bool orig);
//	virtual void Undelivered(int seq, int len, bool orig);
//	virtual void EndpointEOF(TCP_Reassembler* endp);
//
//	static Analyzer* InstantiateAnalyzer(Connection* conn)
//		{ return new Syslog_TCP_Analyzer_binpac(conn); }
//
//	static bool Available()
//		{ return (Syslog_request || Syslog_full_request) && FLAGS_use_binpac; }
//
//protected:
//	binpac::Syslog_on_TCP::Syslog_TCP_Conn* interp;
//};
//
#endif
