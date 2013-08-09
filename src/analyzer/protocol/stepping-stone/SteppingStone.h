// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_STEPPING_STONE_STEPPINGSTONE_H
#define ANALYZER_PROTOCOL_STEPPING_STONE_STEPPINGSTONE_H

#include "Queue.h"
#include "analyzer/protocol/tcp/TCP.h"

class NetSessions;

namespace analyzer { namespace stepping_stone {

class SteppingStoneEndpoint;
class SteppingStoneManager;

declare(PQueue,SteppingStoneEndpoint);
declare(PDict,SteppingStoneEndpoint);

class SteppingStoneEndpoint : public BroObj {
public:
	SteppingStoneEndpoint(tcp::TCP_Endpoint* e, SteppingStoneManager* m);
	~SteppingStoneEndpoint();
	void Done();

	int DataSent(double t, int seq, int len, int caplen, const u_char* data,
		     const IP_Hdr* ip, const struct tcphdr* tp);

protected:
	void Event(EventHandlerPtr f, int id1, int id2 = -1);
	void CreateEndpEvent(int is_orig);

	tcp::TCP_Endpoint* endp;
	int stp_max_top_seq;
	double stp_last_time;
	double stp_resume_time;
	SteppingStoneManager* stp_manager;

	// Hashes for inbound/outbound endpoints that are correlated
	// at least once with this endpoint.  They are necessary for
	// removing correlated endpoint pairs in Bro, since there is
	// no LOOP in Bro language.
	int stp_id;
	HashKey* stp_key;
	PDict(SteppingStoneEndpoint) stp_inbound_endps;
	PDict(SteppingStoneEndpoint) stp_outbound_endps;
};

class SteppingStone_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	SteppingStone_Analyzer(Connection* c);
	virtual ~SteppingStone_Analyzer() {};

	virtual void Init();
	virtual void Done();

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SteppingStone_Analyzer(conn); }

protected:
	// We support both packet and stream input and can be put in place even
	// if the TCP analyzer is not yet reassebmling.
	virtual void DeliverPacket(int len, const u_char* data, bool is_orig,
					int seq, const IP_Hdr* ip, int caplen);
	virtual void DeliverStream(int len, const u_char* data, bool is_orig);

	int orig_stream_pos;
	int resp_stream_pos;

	SteppingStoneManager* stp_manager;
	SteppingStoneEndpoint* orig_endp;
	SteppingStoneEndpoint* resp_endp;
};

// Manages ids for the possible stepping stone connections.
class SteppingStoneManager {
public:
	SteppingStoneManager()		{ endp_cnt = 0; }

	PQueue(SteppingStoneEndpoint)& OrderedEndpoints()
		{ return ordered_endps; }

	// Use postfix ++, since the first ID needs to be even.
	int NextID()			{ return endp_cnt++; }

protected:
	PQueue(SteppingStoneEndpoint) ordered_endps;
	int endp_cnt;
};

} } // namespace analyzer::* 

#endif /* steppingstone_h */
