// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Tag.h"
#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/session/Manager.h"

namespace zeek::analyzer::pia
	{
class PIA_TCP;
	}
namespace zeek::analyzer::tcp
	{
class TCP_Reassembler;
	}

namespace zeek::packet_analysis::TCP
	{

constexpr bool DEBUG_tcp_data_sent = false;
constexpr bool DEBUG_tcp_connection_close = false;

class TCPAnalyzer;

class TCPSessionAdapter final : public packet_analysis::IP::SessionAdapter
	{
public:
	explicit TCPSessionAdapter(Connection* conn);
	~TCPSessionAdapter() override;

	void Process(bool is_orig, const struct tcphdr* tp, int len, const std::shared_ptr<IP_Hdr>& ip,
	             const u_char* data, int remaining);

	void EnableReassembly();

	// Add a child analyzer that will always get the packets,
	// independently of whether we do any reassembly.
	void AddChildPacketAnalyzer(analyzer::Analyzer* a);

	Analyzer* FindChild(analyzer::ID id) override;
	Analyzer* FindChild(zeek::Tag tag) override;
	bool RemoveChildAnalyzer(analyzer::ID id) override;

	// True if the connection has closed in some sense, false otherwise.
	bool IsClosed() const { return orig->did_close || resp->did_close; }
	bool BothClosed() const { return orig->did_close && resp->did_close; }

	bool IsPartial() const { return is_partial; }

	bool HadGap(bool orig) const;

	analyzer::tcp::TCP_Endpoint* Orig() const { return orig; }
	analyzer::tcp::TCP_Endpoint* Resp() const { return resp; }
	int OrigState() const { return orig->state; }
	int RespState() const { return resp->state; }
	int OrigPrevState() const { return orig->prev_state; }
	int RespPrevState() const { return resp->prev_state; }
	uint32_t OrigSeq() const { return orig->LastSeq(); }
	uint32_t RespSeq() const { return resp->LastSeq(); }

	// True if either endpoint still has pending data.  closing_endp
	// is an endpoint that has indicated it is closing (i.e., for
	// which we have seen a FIN) - for it, data is pending unless
	// everything's been delivered up to the FIN.  For its peer,
	// the test is whether it has any outstanding, un-acked data.
	bool DataPending(analyzer::tcp::TCP_Endpoint* closing_endp);

	void SetContentsFile(unsigned int direction, FilePtr f) override;
	FilePtr GetContentsFile(unsigned int direction) const override;

	// From Analyzer.h
	void UpdateConnVal(RecordVal* conn_val) override;

	void AddExtraAnalyzers(Connection* conn) override;

protected:
	friend class analyzer::tcp::TCP_ApplicationAnalyzer;
	friend class analyzer::tcp::TCP_Reassembler;
	friend class analyzer::pia::PIA_TCP;
	friend class packet_analysis::TCP::TCPAnalyzer;

	// Analyzer interface.
	void Init() override;
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip,
	                   int caplen) override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void FlipRoles() override;
	bool IsReuse(double t, const u_char* pkt) override;

	void SetPartialStatus(analyzer::tcp::TCP_Flags flags, bool is_orig);

	// Update the state machine of the TCPs based on the activity.  This
	// includes our pseudo-states such as TCP_ENDPOINT_PARTIAL.
	//
	// On return, do_close is true if we should consider the connection
	// as closed, and gen_event if we should generate an event about
	// this fact.
	void UpdateStateMachine(double t, analyzer::tcp::TCP_Endpoint* endpoint,
	                        analyzer::tcp::TCP_Endpoint* peer, uint32_t base_seq, uint32_t ack_seq,
	                        int len, int32_t delta_last, bool is_orig,
	                        analyzer::tcp::TCP_Flags flags, bool& do_close, bool& gen_event);

	void UpdateInactiveState(double t, analyzer::tcp::TCP_Endpoint* endpoint,
	                         analyzer::tcp::TCP_Endpoint* peer, uint32_t base_seq, uint32_t ack_seq,
	                         int len, bool is_orig, analyzer::tcp::TCP_Flags flags, bool& do_close,
	                         bool& gen_event);

	void UpdateSYN_SentState(analyzer::tcp::TCP_Endpoint* endpoint,
	                         analyzer::tcp::TCP_Endpoint* peer, int len, bool is_orig,
	                         analyzer::tcp::TCP_Flags flags, bool& do_close, bool& gen_event);

	void UpdateEstablishedState(analyzer::tcp::TCP_Endpoint* endpoint,
	                            analyzer::tcp::TCP_Endpoint* peer, analyzer::tcp::TCP_Flags flags,
	                            bool& do_close, bool& gen_event);

	void UpdateClosedState(double t, analyzer::tcp::TCP_Endpoint* endpoint, int32_t delta_last,
	                       analyzer::tcp::TCP_Flags flags, bool& do_close);

	void UpdateResetState(int len, analyzer::tcp::TCP_Flags flags);

	void GeneratePacketEvent(uint64_t rel_seq, uint64_t rel_ack, const u_char* data, int len,
	                         int caplen, bool is_orig, analyzer::tcp::TCP_Flags flags);

	bool DeliverData(double t, const u_char* data, int len, int caplen, const IP_Hdr* ip,
	                 const struct tcphdr* tp, analyzer::tcp::TCP_Endpoint* endpoint,
	                 uint64_t rel_data_seq, bool is_orig, analyzer::tcp::TCP_Flags flags);

	void CheckPIA_FirstPacket(bool is_orig, const IP_Hdr* ip);

	friend class session::detail::Timer;
	void AttemptTimer(double t);
	void PartialCloseTimer(double t);
	void ExpireTimer(double t);
	void ResetTimer(double t);
	void DeleteTimer(double t);
	void ConnDeleteTimer(double t);

	void EndpointEOF(analyzer::tcp::TCP_Reassembler* endp);
	void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
	                      bool gen_event);
	void ConnectionFinished(bool half_finished);
	void ConnectionReset();
	void PacketWithRST();

	void SetReassembler(analyzer::tcp::TCP_Reassembler* rorig,
	                    analyzer::tcp::TCP_Reassembler* rresp);

	uint64_t LastRelDataSeq() const { return rel_data_seq; }

private:
	void SynWeirds(analyzer::tcp::TCP_Flags flags, analyzer::tcp::TCP_Endpoint* endpoint,
	               int data_len) const;

	int ParseTCPOptions(const struct tcphdr* tcp, bool is_orig);

	void CheckRecording(bool need_contents, analyzer::tcp::TCP_Flags flags);

	analyzer::tcp::TCP_Endpoint* orig;
	analyzer::tcp::TCP_Endpoint* resp;

	analyzer::analyzer_list packet_children;
	uint64_t rel_data_seq = 0;

	unsigned int first_packet_seen : 2;
	unsigned int reassembling : 1;
	unsigned int is_partial : 1;
	unsigned int is_active : 1;
	unsigned int finished : 1;

	// Whether we're waiting on final data delivery before closing
	// this connection.
	unsigned int close_deferred : 1;

	// Whether to generate an event when we finally do close it.
	unsigned int deferred_gen_event : 1;

	// Whether we have seen the first ACK from the originator.
	unsigned int seen_first_ACK : 1;
	};

	} // namespace zeek::packet_analysis::tcp
