// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/Analyzer.h"
#include "zeek/IPAddr.h"
#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"
#include "zeek/Conn.h"

namespace zeek::analyzer::pia { class PIA_TCP; }
namespace zeek::packet_analysis::TCP { class TCPSessionAdapter; }

namespace zeek::analyzer::tcp {

class TCP_Endpoint;
class TCP_Reassembler;
class TCP_ApplicationAnalyzer;

using TCP_Analyzer [[deprecated("Remove in v5.1. Use zeek::packet_analysis::TCP::TCPSessionAdapter.")]] =
	packet_analysis::TCP::TCPSessionAdapter;

/**
 * An abstract base class for analyzers for a protocol running on top
 * of TCP.
 */
class TCP_ApplicationAnalyzer : public analyzer::Analyzer {
public:
	TCP_ApplicationAnalyzer(const char* name, Connection* conn)
		: Analyzer(name, conn), tcp(nullptr) { }

	explicit TCP_ApplicationAnalyzer(Connection* conn)
		: Analyzer(conn), tcp(nullptr) { }

	~TCP_ApplicationAnalyzer() override { }

	// This may be nil if we are not directly associated with a TCP
	// analyzer (e.g., we're part of a tunnel decapsulation pipeline).
	packet_analysis::TCP::TCPSessionAdapter* TCP();

	void SetTCP(packet_analysis::TCP::TCPSessionAdapter* arg_tcp)	{ tcp = arg_tcp; }

	// The given endpoint's data delivery is complete.
	virtual void EndpointEOF(bool is_orig);

	// Called whenever an end enters TCP_ENDPOINT_CLOSED or
	// TCP_ENDPOINT_RESET.  If gen_event is true and the connection
	// is now fully closed, a connection_finished event will be
	// generated; otherwise not.
	virtual void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
	                              analyzer::tcp::TCP_Endpoint* peer,
	                              bool gen_event);
	virtual void ConnectionFinished(bool half_finished);
	virtual void ConnectionReset();

	// Called whenever a RST packet is seen - sometimes the invocation
	// of ConnectionReset is delayed.
	virtual void PacketWithRST();

	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;
	void Init() override;

	// This suppresses violations if the TCP connection wasn't
	// fully established.
	void ProtocolViolation(const char* reason,
					const char* data = nullptr, int len = 0) override;

	// "name" and "val" both now belong to this object, which needs to
	//  delete them when done with them.
	virtual void SetEnv(bool orig, char* name, char* val);

private:
	packet_analysis::TCP::TCPSessionAdapter* tcp;
};

class TCP_SupportAnalyzer : public analyzer::SupportAnalyzer {
public:
	TCP_SupportAnalyzer(const char* name, Connection* conn, bool arg_orig)
		: analyzer::SupportAnalyzer(name, conn, arg_orig)	{ }

	~TCP_SupportAnalyzer() override {}

	// These are passed on from TCPSessionAdapter.
	virtual void EndpointEOF(bool is_orig)	{ }
	virtual void ConnectionClosed(TCP_Endpoint* endpoint,
	                              TCP_Endpoint* peer, bool gen_event) 	{ }
	virtual void ConnectionFinished(bool half_finished)	{ }
	virtual void ConnectionReset()	{ }
	virtual void PacketWithRST()	{ }
};


class TCPStats_Endpoint {
public:
	explicit TCPStats_Endpoint(TCP_Endpoint* endp);

	bool DataSent(double t, uint64_t seq, int len, int caplen, const u_char* data,
	              const IP_Hdr* ip, const struct tcphdr* tp);

	RecordVal* BuildStats();

protected:
	TCP_Endpoint* endp;
	int num_pkts;
	int num_rxmit;
	int num_rxmit_bytes;
	int num_in_order;
	int num_OO;
	int num_repl;
	uint64_t max_top_seq;
	int last_id;
	int endian_type;
};

class TCPStats_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit TCPStats_Analyzer(Connection* c);
	~TCPStats_Analyzer() override;

	void Init() override;
	void Done() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new TCPStats_Analyzer(conn); }

protected:
	void DeliverPacket(int len, const u_char* data, bool is_orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	TCPStats_Endpoint* orig_stats;
	TCPStats_Endpoint* resp_stats;
};

} // namespace zeek::analyzer::tcp
