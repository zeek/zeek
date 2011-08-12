// See the file "COPYING" in the main distribution directory for copyright.

#ifndef CONNINFO_H
#define CONNINFO_H

#include "Analyzer.h"
#include "NetVar.h"

class ConnExtInfo_Endpoint {
public:
	ConnExtInfo_Endpoint();
	ConnExtInfo_Endpoint(TCP_Endpoint *te);
	virtual ~ConnExtInfo_Endpoint();

	int AddPacket(int arg_ip_bytes, int ttl);
	RecordVal* GetRecordVal();

	/* for TCP */
	void UpdateWindow(int window);


	double RTT;  // RTT from monitoring point to this endpoint. Measured at handshake time
	int MSS;
	bool SACK_OK;   // can we handle SACKs?
	int SACK_used;  // How often are SACKs actually used ?
	int wscale;     // Announced scale factor. -1 means: none announced
	bool wscale_negotiated;  // did both sides announce scaling? 
	bool ts_opt_used;        // was the Timestamp options used?
	int maxwin;   // the biggest announces recv.wind we've ever seen
	int minwin;   // and the smallest one.
	int syns;     // number of syns from this endpoint
	bool ttl_changed;  // did TTL change after the first packet
	int first_pkt_ttl;  // TTL of first packet
	int pkts_below_seq;   // Number of packets with seq <= max seen sequence
	int bytes_below_seq;  // Number of payload bytes carried in segments
	                      // with seq <= max seen sequence. TODO: should this be IP bytes?
						  // currently not used

	uint32 last_seq;      // highest seq number seen
	bool didrst;          // has sent rst.

protected:
	friend class ConnExtInfo_Analyzer;
	bro_uint_t num_pkts;
	bro_uint_t ip_bytes;     // Sum(ip_len) 
	ConnExtInfo_Endpoint *peer;

private:
	void init_common_members();
};

class ConnExtInfo_Analyzer : public Analyzer {
public:
	ConnExtInfo_Analyzer(Connection* c);
	ConnExtInfo_Analyzer(Connection* c, TCP_Analyzer* tcp);
	virtual ~ConnExtInfo_Analyzer();

	virtual void Init();
	virtual void Done();

	// from Analyzer.h
	virtual void UpdateConnVal(RecordVal *conn_val);
	virtual void FlipRoles();

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ConnExtInfo_Analyzer(conn); }

	static bool Available()	{ return BifConst::get_conn_extensive_info; }

protected:
	typedef enum {
		// Simple state-machine for TCP (handshake)
		// If anything other than SYN, SYNACK, ACK happens,
		// we got to STATE_OTHER
		STATE_INACTIVE,   // No packets seen yet
		STATE_SYN,        // Originator sent syn
		STATE_SYNACK,     // Responder sent syn-ack (after syn)
		STATE_ESTABLISHED, // Originator sent ack (after syn, synack)
		STATE_OTHER,      // anything else has happend
	} ConnExtInfoState;

	virtual void DeliverPacket(int len, const u_char* data, bool is_orig,
					int seq, const IP_Hdr* ip, int caplen);

	void TCP_Packet(const struct tcphdr* tp, bool is_orig, int len);

	ConnExtInfo_Endpoint* orig_info;
	ConnExtInfo_Endpoint* resp_info;

	/* for TCP */
	TCP_Analyzer* tcp;  /* is NULL on non TCP connections */
	ConnExtInfoState state;
	double t_syn, t_synack, t_ack;
};


#endif
