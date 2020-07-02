
#pragma once

#include "analyzer/protocol/udp/UDP.h"
#include "analyzer/protocol/tcp/TCP.h"

#include "syslog_pac.h"

namespace analyzer { namespace syslog {

class Syslog_Analyzer : public zeek::analyzer::Analyzer {
public:
	explicit Syslog_Analyzer(Connection* conn);
	~Syslog_Analyzer() override;

	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Syslog_Analyzer(conn); }

protected:
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
//	virtual void Undelivered(uint64_t seq, int len, bool orig);
//	virtual void EndpointEOF(tcp::TCP_Reassembler* endp);
//
//	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
//		{ return new Syslog_tcp::TCP_Analyzer(conn); }
//
//protected:
//	binpac::Syslog_on_TCP::Syslog_TCP_Conn* interp;
//};
//
} } // namespace analyzer::*
