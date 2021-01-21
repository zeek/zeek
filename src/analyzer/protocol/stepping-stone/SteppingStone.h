// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Queue.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(NetSessions, zeek);

namespace zeek::analyzer::stepping_stone {

class SteppingStoneEndpoint;
class SteppingStoneManager;

class SteppingStoneEndpoint : public Obj {
public:
	SteppingStoneEndpoint(analyzer::tcp::TCP_Endpoint* e, SteppingStoneManager* m);
	~SteppingStoneEndpoint() override;
	void Done();

	bool DataSent(double t, uint64_t seq, int len, int caplen, const u_char* data,
	              const IP_Hdr* ip, const struct tcphdr* tp);

protected:
	void Event(EventHandlerPtr f, int id1, int id2 = -1);
	void CreateEndpEvent(bool is_orig);

	analyzer::tcp::TCP_Endpoint* endp;
	uint64_t stp_max_top_seq;
	double stp_last_time;
	double stp_resume_time;
	SteppingStoneManager* stp_manager;

	// Hashes for inbound/outbound endpoints that are correlated
	// at least once with this endpoint.  They are necessary for
	// removing correlated endpoint pairs in Bro, since there is
	// no LOOP in Bro language.
	int stp_id;
	std::map<int, SteppingStoneEndpoint*> stp_inbound_endps;
	std::map<int, SteppingStoneEndpoint*> stp_outbound_endps;
};

class SteppingStone_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit SteppingStone_Analyzer(Connection* c);
	~SteppingStone_Analyzer() override {};

	void Init() override;
	void Done() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SteppingStone_Analyzer(conn); }

protected:
	// We support both packet and stream input and can be put in place even
	// if the TCP analyzer is not yet reassebmling.
	void DeliverPacket(int len, const u_char* data, bool is_orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;
	void DeliverStream(int len, const u_char* data, bool is_orig) override;

	int orig_stream_pos;
	int resp_stream_pos;

	SteppingStoneManager* stp_manager;
	SteppingStoneEndpoint* orig_endp;
	SteppingStoneEndpoint* resp_endp;
};

// Manages ids for the possible stepping stone connections.
class SteppingStoneManager {
public:

	PQueue<SteppingStoneEndpoint>& OrderedEndpoints()
		{ return ordered_endps; }

	// Use postfix ++, since the first ID needs to be even.
	int NextID()			{ return endp_cnt++; }

protected:
	PQueue<SteppingStoneEndpoint> ordered_endps;
	int endp_cnt = 0;
};

} // namespace zeek::analyzer::stepping_stone
