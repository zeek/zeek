// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/Analyzer.h"
#include "IPAddr.h"
#include "TCP_Endpoint.h"
#include "TCP_Flags.h"
#include "Conn.h"

// We define two classes here:
// - TCP_Analyzer is the analyzer for the TCP protocol itself.
// - TCP_ApplicationAnalyzer is an abstract base class for analyzers for a
//   protocol running on top of TCP.
//
namespace analyzer { namespace pia { class PIA_TCP; } };

namespace analyzer { namespace tcp {

class TCP_Endpoint;
class TCP_ApplicationAnalyzer;
class TCP_Reassembler;

class TCP_Analyzer final : public zeek::analyzer::TransportLayerAnalyzer {
public:
	explicit TCP_Analyzer(Connection* conn);
	~TCP_Analyzer() override;

	void EnableReassembly();

	// Add a child analyzer that will always get the packets,
	// independently of whether we do any reassembly.
	void AddChildPacketAnalyzer(zeek::analyzer::Analyzer* a);

	Analyzer* FindChild(zeek::analyzer::ID id) override;
	Analyzer* FindChild(zeek::analyzer::Tag tag) override;
	bool RemoveChildAnalyzer(zeek::analyzer::ID id) override;

	// True if the connection has closed in some sense, false otherwise.
	bool IsClosed() const	{ return orig->did_close || resp->did_close; }
	bool BothClosed() const	{ return orig->did_close && resp->did_close; }

	bool IsPartial() const	{ return is_partial; }

	bool HadGap(bool orig) const;

	TCP_Endpoint* Orig() const	{ return orig; }
	TCP_Endpoint* Resp() const	{ return resp; }
	int OrigState() const	{ return orig->state; }
	int RespState() const	{ return resp->state; }
	int OrigPrevState() const	{ return orig->prev_state; }
	int RespPrevState() const	{ return resp->prev_state; }
	uint32_t OrigSeq() const	{ return orig->LastSeq(); }
	uint32_t RespSeq() const	{ return resp->LastSeq(); }

	// True if either endpoint still has pending data.  closing_endp
	// is an endpoint that has indicated it is closing (i.e., for
	// which we have seen a FIN) - for it, data is pending unless
	// everything's been delivered up to the FIN.  For its peer,
	// the test is whether it has any outstanding, un-acked data.
	bool DataPending(TCP_Endpoint* closing_endp);

	void SetContentsFile(unsigned int direction, BroFilePtr f) override;
	BroFilePtr GetContentsFile(unsigned int direction) const override;

	// From Analyzer.h
	void UpdateConnVal(zeek::RecordVal *conn_val) override;

	int ParseTCPOptions(const struct tcphdr* tcp, bool is_orig);

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new TCP_Analyzer(conn); }

protected:
	friend class TCP_ApplicationAnalyzer;
	friend class TCP_Reassembler;
	friend class analyzer::pia::PIA_TCP;

	// Analyzer interface.
	void Init() override;
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void FlipRoles() override;
	bool IsReuse(double t, const u_char* pkt) override;

	// Returns the TCP header pointed to by data (which we assume is
	// aligned), updating data, len & caplen.  Returns nil if the header
	// isn't fully present.
	const struct tcphdr* ExtractTCP_Header(const u_char*& data, int& len,
						int& caplen);

	// Returns true if the checksum is valid, false if not (and in which
	// case also updates the status history of the endpoint).
	bool ValidateChecksum(const struct tcphdr* tp, TCP_Endpoint* endpoint,
				int len, int caplen);

	void SetPartialStatus(TCP_Flags flags, bool is_orig);

	// Update the state machine of the TCPs based on the activity.  This
	// includes our pseudo-states such as TCP_ENDPOINT_PARTIAL.
	//
	// On return, do_close is true if we should consider the connection
	// as closed, and gen_event if we shouuld generate an event about
	// this fact.
	void UpdateStateMachine(double t,
			TCP_Endpoint* endpoint, TCP_Endpoint* peer,
			uint32_t base_seq, uint32_t ack_seq,
			int len, int32_t delta_last, bool is_orig, TCP_Flags flags,
			bool& do_close, bool& gen_event);

	void UpdateInactiveState(double t,
				TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				uint32_t base_seq, uint32_t ack_seq,
				int len, bool is_orig, TCP_Flags flags,
				bool& do_close, bool& gen_event);

	void UpdateSYN_SentState(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				 int len, bool is_orig, TCP_Flags flags,
				 bool& do_close, bool& gen_event);

	void UpdateEstablishedState(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				    TCP_Flags flags, bool& do_close, bool& gen_event);

	void UpdateClosedState(double t, TCP_Endpoint* endpoint,
				int32_t delta_last, TCP_Flags flags,
				bool& do_close);

	void UpdateResetState(int len, TCP_Flags flags);

	void GeneratePacketEvent(uint64_t rel_seq, uint64_t rel_ack,
				 const u_char* data, int len, int caplen,
				 bool is_orig, TCP_Flags flags);

	bool DeliverData(double t, const u_char* data, int len, int caplen,
			const IP_Hdr* ip, const struct tcphdr* tp,
			TCP_Endpoint* endpoint, uint64_t rel_data_seq,
			bool is_orig, TCP_Flags flags);

	void CheckRecording(bool need_contents, TCP_Flags flags);
	void CheckPIA_FirstPacket(bool is_orig, const IP_Hdr* ip);

	friend class ConnectionTimer;
	void AttemptTimer(double t);
	void PartialCloseTimer(double t);
	void ExpireTimer(double t);
	void ResetTimer(double t);
	void DeleteTimer(double t);
	void ConnDeleteTimer(double t);

	void EndpointEOF(TCP_Reassembler* endp);
	void ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, bool gen_event);
	void ConnectionFinished(bool half_finished);
	void ConnectionReset();
	void PacketWithRST();

	void SetReassembler(tcp::TCP_Reassembler* rorig, tcp::TCP_Reassembler* rresp);

	// A couple utility functions that may also be useful to derived analyzers.
	static uint64_t get_relative_seq(const TCP_Endpoint* endpoint,
	                               uint32_t cur_base, uint32_t last,
	                               uint32_t wraps, bool* underflow = nullptr);

	static int get_segment_len(int payload_len, TCP_Flags flags);

private:
	TCP_Endpoint* orig;
	TCP_Endpoint* resp;

	using analyzer_list = std::list<zeek::analyzer::Analyzer*>;
	analyzer_list packet_children;

	unsigned int first_packet_seen: 2;
	unsigned int reassembling: 1;
	unsigned int is_partial: 1;
	unsigned int is_active: 1;
	unsigned int finished: 1;

	// Whether we're waiting on final data delivery before closing
	// this connection.
	unsigned int close_deferred: 1;

	// Whether to generate an event when we finally do close it.
	unsigned int deferred_gen_event: 1;

	// Whether we have seen the first ACK from the originator.
	unsigned int seen_first_ACK: 1;
};

class TCP_ApplicationAnalyzer : public zeek::analyzer::Analyzer {
public:
	TCP_ApplicationAnalyzer(const char* name, Connection* conn)
		: Analyzer(name, conn), tcp(nullptr) { }

	explicit TCP_ApplicationAnalyzer(Connection* conn)
		: Analyzer(conn), tcp(nullptr) { }

	~TCP_ApplicationAnalyzer() override { }

	// This may be nil if we are not directly associated with a TCP
	// analyzer (e.g., we're part of a tunnel decapsulation pipeline).
	TCP_Analyzer* TCP()
		{
		return tcp ?
			tcp :
			static_cast<TCP_Analyzer*>(Conn()->FindAnalyzer("TCP"));
		}

	void SetTCP(TCP_Analyzer* arg_tcp)	{ tcp = arg_tcp; }

	// The given endpoint's data delivery is complete.
	virtual void EndpointEOF(bool is_orig);

	// Called whenever an end enters TCP_ENDPOINT_CLOSED or
	// TCP_ENDPOINT_RESET.  If gen_event is true and the connection
	// is now fully closed, a connection_finished event will be
	// generated; otherwise not.
	virtual void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
				      analyzer::tcp::TCP_Endpoint* peer, bool gen_event);
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
	TCP_Analyzer* tcp;
};

class TCP_SupportAnalyzer : public zeek::analyzer::SupportAnalyzer {
public:
	TCP_SupportAnalyzer(const char* name, Connection* conn, bool arg_orig)
		: zeek::analyzer::SupportAnalyzer(name, conn, arg_orig)	{ }

	~TCP_SupportAnalyzer() override {}

	// These are passed on from TCP_Analyzer.
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

	zeek::RecordVal* BuildStats();

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

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new TCPStats_Analyzer(conn); }

protected:
	void DeliverPacket(int len, const u_char* data, bool is_orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	TCPStats_Endpoint* orig_stats;
	TCPStats_Endpoint* resp_stats;
};

} } // namespace analyzer::*
