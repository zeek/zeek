// $Id: TCP_Rewriter.h 6916 2009-09-24 20:48:36Z vern $

#ifndef tcp_rewriter_h
#define tcp_rewriter_h

#include <queue>
#include <set>
using namespace std;

#include <pcap.h>

#include "Val.h"
#include "TCP.h"
#include "Anon.h"
#include "Analyzer.h"

#include "PacketDumper.h"
#include "Rewriter.h"

class TCP_Rewriter;

class TCP_TracePacket : public BroObj, virtual public TracePacket {
public:
	TCP_TracePacket(TCP_Rewriter* trace_rewriter,
			int packet_seq, double t, int is_orig,
			const struct pcap_pkthdr* hdr,
			int MTU, int initial_size);
	~TCP_TracePacket();

	int AppendLinkHeader(const u_char* chunk, int len);
	int AppendIPHeader(const u_char* chunk, int len);
	int AppendTCPHeader(const u_char* chunk, int len);
	int AppendData(const u_char* chunk, int len);

	// Finish() is called before dumping the packet. It sets length
	// fields and computes checksums in TCP/IP headers.
	int Finish(struct pcap_pkthdr*& hdr, const u_char*& pkt, int& length,
		   ipaddr32_t anon_src, ipaddr32_t anon_dst);

	void Reuse();
	int IsReuse() const	{ return reuse; }

	double TimeStamp() const	{ return timestamp; }
	int IsOrig() const	{ return is_orig; }

	const struct pcap_pkthdr* Header() const	{ return &pcap_hdr; }

	const u_char* Buffer() const	{ return pkt; }
	int Length() const	{ return buffer_offset; }

	// Note that Space() does not depend on buffer_size, but depends on MTU.
	int Space() const		{ return mtu - buffer_offset; }
	int IsEmpty() const
		{ return SeqLength() == 0 && ! GetTCP_Flag(TH_RST); }

	uint32 GetSeq() const;
	void SetSeq(uint32 seq);

	uint32 GetAck() const;
	void SetAck(uint32 ack);

	int GetTCP_Flag(int which) const;
	void SetTCP_Flag(int which, int value);

	int SeqLength() const;
	int PayloadLength() const;

	int FINScheduled() const	{ return FIN_scheduled; }
	void ScheduleFIN(int fin = 1)	{ FIN_scheduled = fin; }

	int OnHold() const	{ return on_hold; }
	void SetOnHold(int x)	{ on_hold = x; }

	int HasReservedSlot() const	{ return has_reserved_slot; }
	void AddReservedSlot()		{ ++has_reserved_slot; }

	int PredictedAsEmptyPlaceHolder() const
		{ return predicted_as_empty_place_holder; }
	void PredictAsEmptyPlaceHolder()
		{ predicted_as_empty_place_holder = 1; }

	// Whether the ACK on this packet confirms a content gap on
	// the opposite direction.
	int SeqGap() const	{ return seq_gap; }
	void SetSeqGap(int len)	{ seq_gap = len; }

	int PacketSeq() const		{ return packet_seq; }
	TCP_Rewriter* TraceRewriter() const	{ return trace_rewriter; }

	RecordVal* PacketVal();
	void Describe(ODesc* d) const	{ packet_val->Describe(d); }

protected:
	int Append(const u_char* chunk, int len);

	RecordVal* packet_val;
	TCP_Rewriter* trace_rewriter;
	double timestamp;
	int packet_seq;
	int is_orig;
	struct pcap_pkthdr pcap_hdr;
	int mtu;
	u_char* pkt;	// of maximal length MTU
	int ip_offset, tcp_offset, data_offset;
	int buffer_size;
	int buffer_offset;
	int reuse;	// whether it is an artificially replicated packet
	int FIN_scheduled;
	int on_hold;	// do not dump it in Flush()
	int seq_gap;
	int has_reserved_slot;
	int predicted_as_empty_place_holder;
};

// How a unidirectional flow ends.
#define	END_BY_FIN	1
#define	END_BY_RST	2
#define	END_BY_PEER_RST	4

class TCP_RewriterEndpoint {
public:
	TCP_RewriterEndpoint(TCP_Rewriter* rewriter);
	~TCP_RewriterEndpoint();

	void Init();

	// A packet that contains a TCP segment.
	void NextPacket(TCP_TracePacket* p);
	void WriteData(int len, const u_char* data);
	void SkipGap(int len);

	void Push();
	void ReqAck();
	void Flush();
	void Reset(int self);

	uint32 NextSeq() const	{ return next_seq; }
	int HasPacket() const	{ return next_packet != 0; }
	inline TCP_Analyzer* Analyzer() const;

protected:
	TCP_Rewriter* rewriter;		// TCP rewriter for the connection
	TCP_RewriterEndpoint* peer;	// the peer TCP rewriter endpoint
	TCP_Endpoint* endp;		// the corresponding TCP endpoint

	TCP_TracePacket* next_packet;
	std::queue<BroString*> prolog;

	double last_packet_time;
	uint32 start_seq;	// start seq -- sent in SYN
	uint32 next_seq;	// seq of next packet
	uint32 last_ack;	// last acknowledgement seq

	int please_flush;
	int flush_scheduled;
	int flushed;
	int established;
	int end_of_data;	// is it really useful?
	int there_is_a_gap;

	// Move onto the next packet header.
	void SetNextPacket(TCP_TracePacket* p);

	void PurgeProlog();

	// Pour data into the current packet (next_packet).
	void DoWriteData(int len, const u_char* data);

	// Push the current packet (next_packet) to dumper.
	void PushPacket();

	// Please flush this endpoint after draining events.
	void ScheduleFlush();

	void GenerateFIN();

	// Whether the packet is a "place holder" packet, i.e. it's
	// harmless to omit the packet (except missing the timestamp
	// it contains).
	int IsPlaceHolderPacket(TCP_TracePacket* p);

	void Weird(const char* name) const;
};

class TCP_RewriteSlot {
public:
	TCP_RewriteSlot(TCP_TracePacket* p, unsigned int slot_number);

	void WriteData(int is_orig, int len, const u_char* data);

	void Dump();

	unsigned int Number() const	{ return slot_number; }
	TCP_TracePacket* Packet() const	{ return packet; }

	bool isEmpty() const	{ return buf.empty(); }
protected:
	TCP_Rewriter* rewriter;
	TCP_TracePacket* packet;
	unsigned int slot_number;
	std::queue<BroString*> buf;
};

class TCP_Rewriter : public Rewriter {
public:
	TCP_Rewriter(TCP_Analyzer* analyzer, PacketDumper* dumper, int MTU,
			int wait_for_commitment = 0);
	virtual ~TCP_Rewriter();
	virtual void Done();
	void Funeral();

	// Phase 1 methods: called in packet processing.

	// A TCP/IP packet.
	void NextPacket(int is_orig, double t,
			const struct pcap_pkthdr* pcap_hdr,
			const u_char* pcap_pkt,	// link level header
			int hdr_size,		// link level header size
			const struct ip* ip,
			const struct tcphdr* tp);
	void ContentGap(int is_orig, int len);
	void ScheduleFIN(int is_orig);


	// Phase 2 methods: called in event processing.

	void WriteData(int is_orig, int len, const u_char* data);
	void WriteData(int is_orig, const char* data)
		{ WriteData(is_orig, strlen(data), data); }
	void WriteData(int is_orig, int len, const char* data)
		{ WriteData(is_orig, len, (const u_char*) data); }
	void WriteData(int is_orig, const BroString* str)
		{ WriteData(is_orig, str->Len(), str->Bytes()); }
	void WriteData(int is_orig, StringVal* str)
		{ WriteData(is_orig, str->AsString()); }
	void Push(int is_orig);

	// When wait_for_commitment = 1, packets are not dumped until
	//   CommitPackets().
	// When apply_to_future = 1, the same decision holds for future
	//   packets as well.
	//
	// Regarding why AbortPackets() takes an apply_to_future flag:
	//
	//	The model is that there can be multiple commit/abort stages
	//	during the course of a connection.  At the end of each
	//	stage, a commit or abort decision is made for packets
	//	generated during the stage.  A possible scenario is that
	//	user may want to delete a middle part of a conversation
	//	while keeping the parts before and after intact, and cannot
	//	make the decision until the end of the middle part.

	void AbortPackets(int apply_to_future);
	void CommitPackets(int apply_to_future);

	unsigned int ReserveSlot();
	int SeekSlot(unsigned int slot);
	int ReturnFromSlot();
	int ReleaseSlot(unsigned int slot);

	// Do not anonymize client/server IP address
	int LeaveAddrInTheClear(int is_orig);


	// Phase 3 methods: called in flushing after events.
	// (None, because flushing is done through accessing endpoints directly.)

	// Other methods.

	void DumpPacket(TCP_RewriterEndpoint* endp, TCP_TracePacket* p);

	void Weird(const char* name) const	{ analyzer->Weird(name); }
	TCP_Analyzer* Analyzer() const	{ return analyzer; }

	TCP_Endpoint* GetEndpoint(TCP_RewriterEndpoint* endp);
	TCP_RewriterEndpoint* GetPeer(TCP_RewriterEndpoint* endp);

	TracePacket* CurrentPacket() const	{ return current_packet; }
	TracePacket* RewritePacket() const	{ return next_packet; }

	// Needs to be static because it's passed as a pointer-to-function
	// rather than pointer-to-member-function.
	static int RewriteTCPOption(unsigned int opt, unsigned int optlen,
				const u_char* option, TCP_Analyzer* analyzer,
				bool is_orig, void* cookie);

protected:
	// Under normal circumstances, we always rewrite into the
	// "current packet" of the connection. However, sometimes we'd
	// want to look a few packets ahead before deciding what to
	// rewrite, in which case we may use {hold,release}_packet to
	// specify the packet we are writing to.

	// rewrite_packet (next_packet) always equals to
	// current_packet under *normal mode*. hold_packet(p) dumps
	// all packets *before* p, fixes rewrite_packet at p and turns
	// the connection into *look-ahead* mode. Under look-ahead
	// mode, release_packet(c) dumps all packets of on hold
	// connection and makes the connection returns to normal mode
	// so that rewrite_packet changes along with current_packet.

	// When a packet is held, it is illegal to write to packets on
	// the other half of the connection.

	// Release next_packet
	void ReleaseNextPacket();

	// Hold packet p and release all packets before p.
	void HoldPacket(TCP_TracePacket* p);

	// Release all packets on hold and dump all the packets except
	// the last one, which will be flushed at the end of the event.
	void ReleasePacketsOnHold();

	void CleanUpEmptyPlaceHolders();
	void DoWriteData(int is_orig, int len, const u_char* data);

	TCP_RewriterEndpoint* Endp(int is_orig) const
		{ return is_orig ? orig : resp; }

	TCP_Analyzer* analyzer;
	PacketDumper* dumper;
	TCP_RewriterEndpoint* orig;
	TCP_RewriterEndpoint* resp;
	int MTU;
	int wait_for_commitment;
	int discard_packets;
	std::queue<char*> uncommited_packet_queue;
	int next_packet_seq;
	int packets_rewritten;
	ipaddr32_t anon_addr[2];
	int pending_content_gap;

	TCP_TracePacket* current_packet;
	TCP_TracePacket* next_packet;
	std::deque<TCP_TracePacket*> packets_on_hold;
	int holding_packets;

	TCP_RewriteSlot* current_slot;
	TCP_RewriteSlot* first_slot;
	TCP_RewriteSlot* last_slot;
	std::deque<TCP_RewriteSlot*> slot_queue;
	typedef map<unsigned int, TCP_RewriteSlot*> slot_map_t;
	slot_map_t reserved_slots;
	int highest_slot_number;

	TCP_RewriteSlot* add_slot();
	TCP_RewriteSlot* find_slot(unsigned int slot);

	friend class TCP_RewriteSlot;
	int answered[2];
};

inline TCP_Analyzer* TCP_RewriterEndpoint::Analyzer() const
	{
	return rewriter->Analyzer();
	}

// "Please flush the rewriter endpoint after event processing."
extern void schedule_flush(TCP_RewriterEndpoint* endp);

// "Please call rewriter->Funeral() after event processing."
extern void schedule_funeral(TCP_Rewriter* rewriter);

extern void flush_rewriter_packet();

class TCP_SourcePacket {
public:
	TCP_SourcePacket(const struct pcap_pkthdr* pcap_hdr, const u_char* pcap_pkt);
	~TCP_SourcePacket();

	int Len() const	{ return hdr.caplen; }
	const u_char* Pkt() const	{ return pkt; }
	const struct pcap_pkthdr* Hdr() const	{ return &hdr; }

protected:
	struct pcap_pkthdr hdr;
	u_char* pkt;
};

// Write selected original packets to the trace
class TCP_SourcePacketWriter {
public:
	TCP_SourcePacketWriter(TCP_Analyzer* /* analyzer */,
				PacketDumper* arg_dumper);
	~TCP_SourcePacketWriter();

	void NextPacket(const struct pcap_pkthdr* pcap_hdr,
				const u_char* pcap_pkt);
	void Dump();
	void Abort();

protected:
	PacketDumper* dumper;
	std::queue<TCP_SourcePacket*> source_packets;
	void Purge(bool dump);
};

extern TCP_SourcePacketWriter* get_src_pkt_writer(TCP_Analyzer* analyzer);

#endif
