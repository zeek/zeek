// $Id: TCP_Rewriter.cc 6008 2008-07-23 00:24:22Z vern $

//  Overview of TCP trace rewriter:
//
//  1. Timestamp: Consider every packet arrival at a certain endpoint
//  in the original trace as a tick for the endpoint; a packet will be
//  dumped into the new trace (possibly with different content) in the
//  tick (enforced by flush_rewriter_packet). When the user writes data
//  into the new trace, the packet will carry a timestamp of the
//  current tick, or the next tick if data is generated between
//  ticks. Users may also choose to Push data, in which case the packet
//  carries a timestamp of current network time. This gives us the
//  'freshness' of timestamps.
//
//  2. Ordering of contents: user may choose to push contents in order
//  to enforce ordering of contents between two directions, however,
//  contents MIGHT be already dumped BEFORE they are pushed, once they
//  are written into the trace. (similar to PUSH in TCP)
//
//  3. Acknowledgements: when a packet is dumped at a time when there
//  is no corresponding packet in the original trace, an articial
//  acknowledgement is generated from the peer with the same
//  timestamp. This guarantees that additional packets will have
//  acknowledgements. For those packets dumped at 'ticks', there
//  should be corresponding acknowledgement packets in the original
//  trace already, so we do not generate further artificial
//  acknowledgement packets.
//
//  4. SYN, RST, FIN: SYN/RST packets in the new trace do not carry
//  payloads -- additional packets may be generated for payloads. FIN
//  packets are generated only when user calls ScheduleFIN, which by
//  default corresponds to the moment that contents of the flow is
//  completely delivered, which is usually when the FIN appears in the
//  original trace. Change: now we will try to allow SYN/RST packets
//  to carry payloads if they originally do.

#include "config.h"

#include <assert.h>
#include <stdlib.h>

#include "Event.h"
#include "Net.h"
#include "TCP_Rewriter.h"

#define MSG_PREFIX	"TCP trace rewriter: "
#define DEBUG_MSG_A(x...)
// #define DEBUG_MSG_A	DEBUG_MSG

static IP_IDSet* ip_id_set = 0;	// <IP, IP-ID> pairs in the output trace
int num_packets_held, num_packets_cleaned;

TCP_TracePacket::TCP_TracePacket(TCP_Rewriter* arg_trace_rewriter,
				 int arg_packet_seq, double t, int arg_is_orig,
				 const struct pcap_pkthdr* arg_hdr,
				 int MTU, int initial_size)
	{
	trace_rewriter = arg_trace_rewriter;
	pcap_hdr = *arg_hdr;
	packet_seq = arg_packet_seq;
	timestamp = t;
	is_orig = arg_is_orig;
	mtu = MTU;
	pkt = new u_char[initial_size];
	buffer_size = initial_size;

	buffer_offset = 0;
	ip_offset = tcp_offset = data_offset = -1;
	reuse = 0;
	FIN_scheduled = 0;
	on_hold = 0;
	seq_gap = 0;
	packet_val = 0;
	packet_val = PacketVal();
	has_reserved_slot = 0;
	predicted_as_empty_place_holder = 0;
	}

TCP_TracePacket::~TCP_TracePacket()
	{
	packet_val->SetOrigin(0);
	Unref(packet_val);
	if ( pkt )
		delete [] pkt;
	}

int TCP_TracePacket::AppendLinkHeader(const u_char* chunk, int len)
	{
	if ( ip_offset >= 0 && ip_offset != buffer_offset )
		internal_error(MSG_PREFIX "link header must be appended before IP header");

	if ( ! Append(chunk, len) )
		return 0;

	ip_offset = buffer_offset;
	return 1;
	}

int TCP_TracePacket::AppendIPHeader(const u_char* chunk, int len)
	{
	if ( tcp_offset >= 0 && tcp_offset != buffer_offset )
		internal_error(MSG_PREFIX "IP header must be appended before tcp header");

	if ( ! Append(chunk, len) )
		return 0;

	tcp_offset = buffer_offset;
	return 1;
	}

int TCP_TracePacket::AppendTCPHeader(const u_char* chunk, int len)
	{
	if ( data_offset >= 0 && data_offset != buffer_offset )
		internal_error(MSG_PREFIX "tcp header must be appended before payload");

	if ( tcp_offset == buffer_offset )
		{ // first TCP header chunk
		int extra = (tcp_offset - ip_offset) % 4;
		if ( extra )
			{
			DEBUG_MSG(MSG_PREFIX "padding IP header");
			if ( ! AppendIPHeader(0, 4 - extra) )
				return 0;
			}
		}

	if ( ! Append(chunk, len) )
		return 0;

	data_offset = buffer_offset;
	return 1;
	}

int TCP_TracePacket::AppendData(const u_char* chunk, int len)
	{
	// All headers must be appended before any data.
	ASSERT(ip_offset >= 0 && tcp_offset >= 0 && data_offset >= 0);

	if ( data_offset == buffer_offset )
		{ // first data chunk
		int extra = (data_offset - tcp_offset) % 4;
		if ( extra )
			{
			DEBUG_MSG(MSG_PREFIX "%.6f padding tcp header -- original header range: %d - %d\n",
					network_time, tcp_offset, data_offset);
			if ( ! AppendTCPHeader(0, 4 - extra) )
				return 0;
			}
		}

	if ( ! Append(chunk, len) )
		return 0;

	return 1;
	}

int TCP_TracePacket::Append(const u_char* chunk, int len)
	{
	if ( buffer_offset + len > buffer_size )
		{
		if ( buffer_offset + len > mtu )
			return 0;

		u_char* tmp = new u_char[mtu];
		for ( int i = 0 ; i < buffer_size; ++i )
			tmp[i] = pkt[i];

		delete [] pkt;
		pkt = tmp;
		buffer_size = mtu;
		}

	ASSERT(buffer_offset + len <= buffer_size);

	if ( chunk )
		{
		if ( pkt + buffer_offset != chunk )
			memcpy(pkt + buffer_offset, chunk, len);
		}
	else
		// Fill with 0.
		memset(pkt + buffer_offset, 0, len);

	buffer_offset += len;
	return 1;
	}

uint32 TCP_TracePacket::GetSeq() const
	{
	ASSERT(tcp_offset >= ip_offset + int(sizeof(struct ip)) &&
	       buffer_offset >= tcp_offset + int(sizeof(struct tcphdr)));

	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);
	return ntohl(tp->th_seq);
	}

void TCP_TracePacket::SetSeq(uint32 seq)
	{
	ASSERT(tcp_offset >= ip_offset + int(sizeof(struct ip)) &&
	       buffer_offset >= tcp_offset + int(sizeof(struct tcphdr)));

	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);
	tp->th_seq = htonl(seq);
	}

uint32 TCP_TracePacket::GetAck() const
	{
	ASSERT(tcp_offset >= ip_offset + int(sizeof(struct ip)) &&
	       buffer_offset >= tcp_offset + int(sizeof(struct tcphdr)));

	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);
	return ntohl(tp->th_ack);
	}

void TCP_TracePacket::SetAck(uint32 ack)
	{
	ASSERT(tcp_offset >= ip_offset + int(sizeof(struct ip)) &&
	       buffer_offset >= tcp_offset + int(sizeof(struct tcphdr)));

	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);
	tp->th_ack = htonl(ack);
	}

int TCP_TracePacket::GetTCP_Flag(int which) const
	{
	ASSERT(tcp_offset >= ip_offset + int(sizeof(struct ip)) &&
	       buffer_offset >= tcp_offset + int(sizeof(struct tcphdr)));

	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);
	return tp->th_flags & which;
	}

void TCP_TracePacket::SetTCP_Flag(int which, int value)
	{
	ASSERT(tcp_offset >= ip_offset + int(sizeof(struct ip)) &&
	       buffer_offset >= tcp_offset + int(sizeof(struct tcphdr)));

	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);

	if ( value )
		tp->th_flags |= which;
	else
		tp->th_flags &= (~which);
	}

int TCP_TracePacket::PayloadLength() const
	{
	if ( data_offset < 0 )
		return 0;

	return buffer_offset - data_offset;
	}

int TCP_TracePacket::SeqLength() const
	{
	int len = PayloadLength();
	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);

	if ( tp->th_flags & TH_SYN )
		++len;

	if ( tp->th_flags & TH_FIN )
		++len;

	return len;
	}

int TCP_TracePacket::Finish(struct pcap_pkthdr*& hdr,
			    const u_char*& arg_pkt, int& length,
			    ipaddr32_t anon_src, ipaddr32_t anon_dst)
	{
	// Set length fields in headers and compute checksums.
	if ( tcp_offset < ip_offset + int(sizeof(struct ip)) ||
	     data_offset < tcp_offset + int(sizeof(struct tcphdr)) )
		return 0;

	struct ip* ip = (struct ip*) (pkt + ip_offset);
	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);

	// TCP header.
	ASSERT((data_offset - tcp_offset) % 4 == 0);

	tp->th_off = (data_offset - tcp_offset) >> 2;
	tp->th_x2 = 0;

	// Shall we instead let URG flag&point stay?
	// tp->th_flags &= (~TH_URG);	// set URG to 0
	// tp->th_urp = 0;		// clear urgent pointer

	// Fix IP addresses before computing the TCP checksum
	if ( anonymize_ip_addr )
		{
		ip->ip_src.s_addr = anon_src;
		ip->ip_dst.s_addr = anon_dst;
		}

	tp->th_sum = 0;
	tp->th_sum = 0xffff - tcp_checksum(ip, tp, PayloadLength());

	// IP header.

	// What to do with ip_id? One way is to choose a pseudo-random
	// number as the new id. We try to keep the original ID unless
	// it would cause a conflict, in which case we increment the
	// ID till there is no conflict.
	//
	// This is too expensive -- and ID conflicts do not really
	// matter because there will never be fragmentation.
	// Fix: just keep the original ID.
	// ip->ip_id = NextIP_ID(ip->ip_src.s_addr, ip->ip_id);

	ASSERT((tcp_offset - ip_offset) % 4 == 0);
	ip->ip_hl = (tcp_offset - ip_offset) >> 2;
	ip->ip_len = htons(buffer_offset - ip_offset);
	ip->ip_off = 0;		// DF = 0, MF = 0, offset = 0
	ip->ip_sum = 0;
	ip->ip_sum = 0xffff - ones_complement_checksum((const void*) ip, tcp_offset - ip_offset, 0);

	// Link level header:
	// Question: what to do with the link level header? Currently we just
	// keep the original header, even though the length field can
	// be incorrect. ###

	if ( timestamp < trace_rewriter->RewritePacket()->TimeStamp() )
		// For out of order rewriting.
		timestamp = trace_rewriter->RewritePacket()->TimeStamp();

	// The below works around a potential type incompatibility
	// on systems where pcap's timeval is different from the
	// system-wide one. --cpk
	//
	timeval tv_tmp = double_to_timeval(timestamp);
	pcap_hdr.ts.tv_sec = tv_tmp.tv_sec;
	pcap_hdr.ts.tv_usec = tv_tmp.tv_usec;
	pcap_hdr.caplen = pcap_hdr.len = buffer_offset;

	hdr = &pcap_hdr;
	arg_pkt = pkt;
	length = buffer_offset;

	return 1;
	}

void TCP_TracePacket::Reuse()
	{
	reuse = 1;

	timestamp = trace_rewriter->RewritePacket()->TimeStamp();

	// Question 1: Shall we keep TCP options in the header? Note
	// that the TCP header of a packet is sometimes replicated in
	// the rewritten trace (because we reuse headers). When an
	// option have idempotent semantics, it is safe to keep the
	// option; otherwise we should include the option only in the
	// first one among replicated copies. Currently we keep
	// options for simplicity and wait for things to happen. ###

	struct tcphdr* tp = (struct tcphdr*) (pkt + tcp_offset);
	tp->th_flags = 0;

	// Clear all TCP options.
	unsigned int prev_data_offset = data_offset;
	buffer_offset = data_offset = tcp_offset + sizeof(struct tcphdr);
	if ( prev_data_offset - tcp_offset > sizeof(*tp) )
		TCP_Analyzer::ParseTCPOptions(tp,
					TCP_Rewriter::RewriteTCPOption,
					trace_rewriter->Analyzer(), is_orig, this);
	}

RecordVal* TCP_TracePacket::PacketVal()
	{
	if ( ! packet_val )
		{
		packet_val = new RecordVal(packet_type);
		packet_val->Assign(0, TraceRewriter()->Analyzer()->BuildConnVal());
		packet_val->Assign(1, new Val(IsOrig(), TYPE_BOOL));
		packet_val->Assign(2, new Val(PacketSeq(), TYPE_COUNT));
		packet_val->Assign(3, new Val(TimeStamp(), TYPE_TIME));
		packet_val->SetOrigin(this);
		}
	else
		Ref(packet_val);

	return packet_val;
	}

uint16 NextIP_ID(const uint32 src_addr, const uint16 id)
	{
	if ( ip_id_set == 0 )
		ip_id_set = new IP_IDSet();

	IP_ID ipid;
	ipid.ip = src_addr;
	ipid.id = id;

	while ( ip_id_set->find(ipid) != ip_id_set->end() )
		{
		ipid.id = (ipid.id + 1) & 0xffff;

		if ( ipid.id == id )
			{ // clear all entries of the IP
			IP_ID first_id, last_id;
			first_id.ip = last_id.ip = src_addr;
			first_id.id = 0; last_id.id = 0xffff;
			ip_id_set->erase(ip_id_set->find(first_id),
						ip_id_set->find(last_id));
			}
		}

	ip_id_set->insert(ipid);

	return uint16(ipid.id & 0xffff);
	}

TCP_RewriterEndpoint::TCP_RewriterEndpoint(TCP_Rewriter* arg_rewriter)
	{
	rewriter = arg_rewriter;
	next_packet = 0;
	endp = 0;
	established = 0;
	end_of_data = 0;
	peer = 0;
	last_ack = 0;
	last_packet_time = -1;
	please_flush = 0;
	flushed = 1;
	flush_scheduled = 0;
	there_is_a_gap = 0;
	}

TCP_RewriterEndpoint::~TCP_RewriterEndpoint()
	{
	if ( ! prolog.empty() )
		{
		if ( ! next_packet )
			Weird(MSG_PREFIX "end point has data, but hasn't got any packet till destruction.");
		else
			internal_error(MSG_PREFIX "prolog should've been purged on the very first packet.");

		while ( ! prolog.empty() )
			{
			delete prolog.front();
			prolog.pop();
			}
		}

	if ( ! end_of_data && next_packet && ! next_packet->IsEmpty() )
		Weird(fmt(MSG_PREFIX "end of data missing before deleting the connection: %.6f",
			  next_packet->TimeStamp()));

	if ( next_packet )
		Unref(next_packet);
	}

void TCP_RewriterEndpoint::Init()
	{
	// This cannot be put into the constructor because it requires
	// existence of the peer.
	peer = rewriter->GetPeer(this);
	}

// NextPacket sets 'ticks' of packet dumping according to packet
// arrival in the original sequence.
void TCP_RewriterEndpoint::NextPacket(TCP_TracePacket* p)
	{
	please_flush = 1;
	flushed = 0;
	last_packet_time = p->TimeStamp();

	if ( ! endp )
		endp = rewriter->GetEndpoint(this);

	if ( endp->state == TCP_ENDPOINT_ESTABLISHED )
		established = 1;

	if ( ! next_packet || p->GetTCP_Flag(TH_SYN) )
		{
		if ( ! p->GetTCP_Flag(TH_SYN | TH_RST) &&
		     ! rewriter->Analyzer()->IsPartial() )
			Weird(MSG_PREFIX "first packet is not SYN or RST");

		start_seq = next_seq = p->GetSeq();
		}

	SetNextPacket(p);
	ScheduleFlush();
	}

void TCP_RewriterEndpoint::WriteData(int len, const u_char* data)
	{
	if ( end_of_data & (END_BY_FIN | END_BY_RST) )
		Weird(MSG_PREFIX "write after end of data");

	if ( ! next_packet )
		{
		// Till anybody really wants to use the prolog ...
		run_time(fmt("pushing %d bytes into prolog", len));
		prolog.push(new BroString(data, len, 0));
		}
	else
		{
		// Originally we did not send data along with SYN or RST.
		// if ( next_packet->GetTCP_Flag(TH_SYN | TH_RST) )
		//	internal_error("SYN/RST packet not immediately flushed");

		// Question: shall we send data along with the ACK in the
		// connection's three way handshake? Here it may do so.

		DoWriteData(len, data);

		if ( please_flush )
			ScheduleFlush();
		}
	}

void TCP_RewriterEndpoint::SkipGap(int len)
	{
	next_seq += len;
	there_is_a_gap = 1;

	if ( next_packet )
		next_packet->SetSeqGap(0);
	}

void TCP_RewriterEndpoint::Push()
	{
	if ( ! next_packet )
		return;

	next_packet->SetTCP_Flag(TH_PUSH, 1);
	PushPacket();
	}

void TCP_RewriterEndpoint::ReqAck()
	{
	if ( ! next_packet )
		return;

	PushPacket();
	}

void TCP_RewriterEndpoint::Flush()
	{
	if ( ! next_packet || next_packet->OnHold() )
		// This may happen after the code change in
		// TCP_Connection::NextPacket -- not every packet
		// reaches the TCP rewriter.  Also, do not dump a packet
		// on hold -- the packet will be flushed later.
		// internal_error(MSG_PREFIX "flush before packet arrival");
		return;

	DEBUG_MSG_A("preparing to flush packet %d (%.6f)\n", next_packet->PacketSeq(), next_packet->TimeStamp());
	if ( next_packet->FINScheduled() )
		GenerateFIN();

	if ( please_flush )
		{
		DEBUG_MSG_A("Flush packet %d (%.6f)\n", next_packet->PacketSeq(), next_packet->TimeStamp());
		PushPacket();
		}

	if ( ! next_packet->IsEmpty() )
		{
		internal_error(MSG_PREFIX "packet is not empty after flushing");
		}

	flush_scheduled = 0;
	}

void TCP_RewriterEndpoint::ScheduleFlush()
	{
	if ( ! flush_scheduled )
		{
		schedule_flush(this);
		flush_scheduled = 1;
		DEBUG_MSG_A("%.6f flush scheduled for packet %d (%.6f)\n", network_time, next_packet->PacketSeq(), next_packet->TimeStamp());
		}
	}

void TCP_RewriterEndpoint::GenerateFIN()
	{
	if ( end_of_data & END_BY_FIN )
		return;

	DEBUG_MSG_A("FIN at %.6f\n", next_packet->TimeStamp());
	end_of_data |= END_BY_FIN;

	if ( ! next_packet )
		// Weird(MSG_PREFIX "FIN before packet arrival");
		internal_error(MSG_PREFIX "FIN before packet arrival");
	else
		{
		next_packet->ScheduleFIN(0);
		next_packet->SetTCP_Flag(TH_FIN, 1);
		please_flush = 1;
		}
	}

void TCP_RewriterEndpoint::Reset(int self)
	{
	DEBUG_MSG_A("%.6f end by RST (empty = %d)\n", network_time, next_packet ? next_packet->IsEmpty() : -1);
	if ( self )
		end_of_data |= END_BY_RST;
	else
		end_of_data |= END_BY_PEER_RST;
	}

void TCP_RewriterEndpoint::SetNextPacket(TCP_TracePacket* p)
	{
	if ( next_packet )
		{
		if ( ! next_packet->IsEmpty() || next_packet->OnHold() )
			internal_error(MSG_PREFIX "next packet (%.6f) arrives before the previous packet (%.6f) is flushed", p->TimeStamp(), next_packet->TimeStamp());
			// PushPacket();

		Unref(next_packet);
		}

	next_packet = p;

	if ( next_packet->SeqGap() > 0 )
		peer->SkipGap(next_packet->SeqGap());

	// next_packet->SetTCP_Flag(TH_PUSH, 0);

	// Do not send FIN at this moment because FIN may arrive out
	// of order -- wait till all contents are delivered
	next_packet->SetTCP_Flag(TH_FIN, 0);

	if ( ! prolog.empty() )
		{
		// Do not put prolog into SYN/RST packets
		if ( next_packet->GetTCP_Flag(TH_SYN | TH_RST) )
			PushPacket();
		PurgeProlog();
		}
	}

void TCP_RewriterEndpoint::PurgeProlog()
	{
	while ( ! prolog.empty() )
		{
		BroString* s = prolog.front();
		WriteData(s->Len(), s->Bytes());
		prolog.pop();
		delete s;
		}
	}

void TCP_RewriterEndpoint::DoWriteData(int len, const u_char* data)
	{
	ASSERT(next_packet);

	while ( len > 0 )
		{
		int left = next_packet->Space();

		if ( ! left )
			{
			PushPacket();
			left = next_packet->Space();
			}

		if ( left > len )
			left = len;

		if ( ! next_packet->AppendData(data, left) )
			ASSERT(0);

		data += left;
		len -= left;
		please_flush = 1;
		}
	}

int TCP_RewriterEndpoint::IsPlaceHolderPacket(TCP_TracePacket* p)
	{
	return p->SeqLength() == 0 &&
	       ! p->GetTCP_Flag(TH_SYN | TH_RST | TH_FIN | TH_URG ) &&
	       ! (p->GetTCP_Flag(TH_ACK) && p->GetAck() > last_ack);
	}

void TCP_RewriterEndpoint::PushPacket()
	{
	if ( ! next_packet )
		{
		internal_error(MSG_PREFIX "cannot push packet before packet arrival");
		return;
		}

	// Set sequence number ...
	next_packet->SetSeq(next_seq);
	int seq_len = next_packet->SeqLength();

	next_seq += seq_len;

	// ... and acknowledge peer's recently dumped packet.
	if ( next_packet->GetTCP_Flag(TH_SYN | TH_RST) &&
	     ! next_packet->GetTCP_Flag(TH_ACK) )
		{
		next_packet->SetTCP_Flag(TH_ACK, 0);
		next_packet->SetAck(0);
		}
	else
		{
		next_packet->SetTCP_Flag(TH_ACK, 1);
		if ( peer->HasPacket() )
			next_packet->SetAck(peer->NextSeq());
		}

	int RST = next_packet->GetTCP_Flag(TH_RST);

#if 0
	// With the feature of reserve_rewrite_slot, packet dumping can
	// be delayed.

	// Enforce the order of timestamps; but delayed FIN is OK
	// when there is a gap.
	if ( next_packet->TimeStamp() < network_time &&
	     ! (next_packet->GetTCP_Flag(TH_FIN) && there_is_a_gap) )
		{
		Weird(MSG_PREFIX "delayed packet");
		Weird(fmt(MSG_PREFIX "packet time %.6f, dumping time %.6f\n",
			 next_packet->TimeStamp(), network_time));
		}
#endif

	if ( ! IsPlaceHolderPacket(next_packet) ||
	     ! omit_rewrite_place_holder )
		{
		if ( next_packet->PredictedAsEmptyPlaceHolder() )
			{
			DEBUG_MSG("The packet to dump (%.6f, %d, %d, %s%s%s%s, %u > %u) was predicted to be an empty place holder.",
				next_packet->TimeStamp(), next_packet->SeqLength(), next_packet->PayloadLength(),
				next_packet->GetTCP_Flag(TH_SYN) ? "S" : "",
				next_packet->GetTCP_Flag(TH_RST) ? "R" : "",
				next_packet->GetTCP_Flag(TH_FIN) ? "F" : "",
				next_packet->GetTCP_Flag(TH_URG) ? "U" : "",
				next_packet->GetAck(), last_ack);
			}

		rewriter->DumpPacket(this, next_packet);
		}

	if ( next_packet->GetTCP_Flag(TH_ACK) &&
	     next_packet->GetAck() > last_ack )
		last_ack = next_packet->GetAck();

	// Reuse the packet headers.
	next_packet->Reuse();

	if ( ! next_packet->FINScheduled() )
		{
		please_flush = 0;
		if ( ! next_packet->IsEmpty() )
			internal_error("should have been cleared");
		}

	if ( RST )
		{
		Reset(1);	// itself ...
		peer->Reset(0); // ... and peer
		return;
		}

	// Question: do we need to request an ACK? Yes, if the packet
	// is an artificially generated packet.
	if ( seq_len > 0 &&
	     next_packet->TimeStamp() < rewriter->RewritePacket()->TimeStamp() )
		peer->ReqAck();
	}

void TCP_RewriterEndpoint::Weird(const char* name) const
	{
#ifdef DEBUG_BRO
	rewriter->Weird(name);
#endif
	}

TCP_Rewriter::TCP_Rewriter(TCP_Analyzer* arg_analyzer, PacketDumper* arg_dumper,
				int arg_MTU, int arg_wait_for_commitment)
	{
	analyzer = arg_analyzer;
	dumper = arg_dumper;
	MTU = arg_MTU;
	wait_for_commitment = arg_wait_for_commitment;
	discard_packets = 0;	// till AbortPackets(1);

	packets_rewritten = 0;
	next_packet_seq = 0;
	pending_content_gap = 0;

	orig = new TCP_RewriterEndpoint(this);
	resp = new TCP_RewriterEndpoint(this);

	orig->Init();
	resp->Init();

	anon_addr[0] = anon_addr[1] = 0;

	if ( anonymize_ip_addr )
		{
		anon_addr[0] = anonymize_ip(to_v4_addr(analyzer->Conn()->OrigAddr()),
						ORIG_ADDR);
		anon_addr[1] = anonymize_ip(to_v4_addr(analyzer->Conn()->RespAddr()),
						RESP_ADDR);
		}

	holding_packets = 0;
	current_packet = next_packet = 0;

	current_slot = first_slot = last_slot = 0;
	highest_slot_number = 0;
	answered[0] = answered[1] = 0;
	}

void TCP_Rewriter::Done()
	{
	// The wrap-up work needs to be done *after* event processing,
	// therefore we schedule a funeral to be held right before
	// packets are flushed.
	schedule_funeral(this);
	}

void TCP_Rewriter::Funeral()
	{
	if ( ! uncommited_packet_queue.empty() )
		{
		warn(fmt(MSG_PREFIX
			 "rewriter gets neither commit or abort, "
			 "and %d packets will be discarded",
			 int(uncommited_packet_queue.size())));
		AbortPackets(0);
		}

	if ( ! slot_queue.empty() )
		{
		run_time("reserved slots are not completely released at the end of rewriter %s", analyzer->Conn());
		for ( slot_map_t::iterator it = reserved_slots.begin();
			it != reserved_slots.end();
			++it )
			{
			TCP_RewriteSlot* slot = it->second;
			run_time(fmt("unreleased slot: %d", slot->Number()));
			}

		while ( ! slot_queue.empty() )
			{
			TCP_RewriteSlot* slot = slot_queue.front();
			slot_queue.pop_front();
			slot->Dump();
			delete slot;
			}

		reserved_slots.clear();
		ReleasePacketsOnHold();
		}

	if ( ! packets_on_hold.empty() )
		{
		run_time("packets on hold at the end of rewriter %s", analyzer->Conn());
		ReleasePacketsOnHold();
		// And release the last one.
		Endp(next_packet->IsOrig())->Flush();
		}
	}

TCP_Rewriter::~TCP_Rewriter()
	{
	delete orig;
	delete resp;
	}

void TCP_Rewriter::NextPacket(int is_orig, double t,
			      const struct pcap_pkthdr* pcap_hdr,
			      const u_char* pcap_pkt, int hdr_size,
			      const struct ip* ip,
			      const struct tcphdr* tp)
	{
	unsigned int ip_hdr_len = ip->ip_hl * 4;
	unsigned int tcp_hdr_len = tp->th_off * 4;

	TCP_TracePacket* p =
		new TCP_TracePacket(this, ++next_packet_seq, t,
					is_orig, pcap_hdr, MTU,
					hdr_size + ip_hdr_len + tcp_hdr_len);

	if ( ! p->AppendLinkHeader(pcap_pkt, hdr_size) )
		internal_error(MSG_PREFIX "cannot append headers -- check MTU");

	if ( ! p->AppendIPHeader((const u_char*)ip, sizeof(*ip)) )
		internal_error(MSG_PREFIX "cannot append headers -- check MTU");

	if ( ip_hdr_len > sizeof(*ip) )
		{
		// TODO: re-write IP options.
		}

	if ( ! p->AppendTCPHeader((const u_char*)tp, sizeof(*tp)) )
		internal_error(MSG_PREFIX "cannot append headers -- check MTU");

	// Rewrite TCP options.
	if ( tcp_hdr_len > sizeof(*tp) )
		TCP_Analyzer::ParseTCPOptions(tp, RewriteTCPOption,
						analyzer, is_orig, p);

	// Pad the TCP header.
	p->AppendData(0, 0);

	// Before setting current_packet to p, first clean up empty
	// place holders to save memory space.
	if ( omit_rewrite_place_holder && holding_packets )
		CleanUpEmptyPlaceHolders();

	current_packet = p;

	if ( pending_content_gap )
		{
		// A packet triggers a content gap only in the other
		// direction.
		if ( current_packet->IsOrig() )
			pending_content_gap = -pending_content_gap;

		if ( pending_content_gap < 0 )
			internal_error("content gap out of sync with packet");

		current_packet->SetSeqGap(pending_content_gap);
		pending_content_gap = 0;
		}

	if ( current_slot )
		add_slot();

	if ( ! holding_packets )
		{
		next_packet = p;
		Endp(is_orig)->NextPacket(p);
		}
	else
		{
		DEBUG_MSG_A("packet %d (%.6f) on hold\n",
				p->PacketSeq(), p->TimeStamp());
		packets_on_hold.push_back(p);
		++num_packets_held;
		}
	}

void TCP_Rewriter::ContentGap(int is_orig, int len)
	{
	if ( is_orig )
		pending_content_gap = len;
	else
		pending_content_gap = -len;
	}

void TCP_Rewriter::ScheduleFIN(int is_orig)
	{
	if ( current_packet && current_packet->IsOrig() == is_orig )
		current_packet->ScheduleFIN();

	// Otherwise just ignore the FIN.
	// Endp(is_orig)->ScheduleFIN();
	}

void TCP_Rewriter::WriteData(int is_orig, int len, const u_char* data)
	{
	if ( ! current_slot )
		DoWriteData(is_orig, len, data);
	else
		current_slot->WriteData(is_orig, len, data);
	}

void TCP_Rewriter::DoWriteData(int is_orig, int len, const u_char* data)
	{
	if ( is_orig != next_packet->IsOrig() )
		{
		// Weird(fmt("%.6f rewriting packet on the opposite direction", network_time));
		}

	Endp(is_orig)->WriteData(len, data);
	}

void TCP_Rewriter::Push(int is_orig)
	{
	Endp(is_orig)->Push();
	}

void TCP_Rewriter::DumpPacket(TCP_RewriterEndpoint* endp, TCP_TracePacket* p)
	{
	struct pcap_pkthdr* hdr;
	const u_char* pkt;
	int length;
	ipaddr32_t anon_src, anon_dst;		// anonymized IP addresses

	if ( discard_packets )
		return;

	if ( endp == orig )
		{
		anon_src = anon_addr[0];
		anon_dst = anon_addr[1];
		}
	else
		{
		anon_src = anon_addr[1];
		anon_dst = anon_addr[0];
		}

	if ( p->Finish(hdr, pkt, length, anon_src, anon_dst) )
		{
		DEBUG_MSG_A("Packet %d (%.6f) dumped at %.6f\n", p->PacketSeq(), p->TimeStamp(), network_time);
		++packets_rewritten;

		if ( ! wait_for_commitment )
			dumper->DumpPacket(hdr, pkt, length);
		else
			{
			char* b = new char[sizeof(struct pcap_pkthdr) + length];
			uncommited_packet_queue.push(b);

			memcpy(b, hdr, sizeof(struct pcap_pkthdr));

			b += sizeof(struct pcap_pkthdr);
			memcpy(b, pkt, length);
			}
		}
	else
		internal_error(MSG_PREFIX "ill formed packet for dumping");
	}

void TCP_Rewriter::ReleaseNextPacket()
	{
	if ( packets_on_hold.empty() )
		{
		internal_error("there is no packet on hold to release");
		return;
		}

	next_packet->SetOnHold(0);
	Endp(next_packet->IsOrig())->Flush();
	packets_on_hold.pop_front();

	if ( ! packets_on_hold.empty() )
		{
		next_packet = packets_on_hold.front();
		Endp(next_packet->IsOrig())->NextPacket(next_packet);
		}
	else
		next_packet = 0;
	}

void TCP_Rewriter::HoldPacket(TCP_TracePacket* p)
	{
	if ( ! next_packet )
		{
		internal_error("should not try to hold a packet before packet arrival");
		return;
		}

	holding_packets = 1;

	while ( next_packet && next_packet->PacketSeq() < p->PacketSeq() )
		ReleaseNextPacket();

	if ( ! next_packet ||
	     next_packet->PacketSeq() != p->PacketSeq() )
		{
		internal_error("packet sequence not found for hold_packet: %d",
		    p->PacketSeq());
		return;
		}

	next_packet->SetOnHold(1);
	if ( packets_on_hold.empty() )
		{
		packets_on_hold.push_back(next_packet);
		++num_packets_held;
		answered[0] = answered[1] = 0;
		}
	}

void TCP_Rewriter::ReleasePacketsOnHold()
	{
	holding_packets = 0;
	if ( packets_on_hold.empty() )
		return;

	while ( packets_on_hold.size() > 1 )
		ReleaseNextPacket();

	next_packet->SetOnHold(0);
	packets_on_hold.pop_front();
	}

void TCP_Rewriter::AbortPackets(int apply_to_future)
	{
	while ( ! uncommited_packet_queue.empty() )
		{
		char* p = uncommited_packet_queue.front();
		uncommited_packet_queue.pop();
		delete [] p;
		}

	if ( apply_to_future )
		discard_packets = 1;
	}

void TCP_Rewriter::CommitPackets(int apply_to_future)
	{
	while ( ! uncommited_packet_queue.empty() )
		{
		struct pcap_pkthdr* hdr =
			(struct pcap_pkthdr*) uncommited_packet_queue.front();

		uncommited_packet_queue.pop();

		dumper->DumpPacket(hdr,
				((u_char*)hdr) + sizeof(struct pcap_pkthdr),
				int((hdr->caplen)));

		delete [] (char*) hdr;
		}

	if ( apply_to_future )
		{ // dump all future packets immediately
		wait_for_commitment = 0;
		discard_packets = 0;
		}
	}

void TCP_Rewriter::CleanUpEmptyPlaceHolders()
	{
	if ( ! last_slot )
		return;

	if ( last_slot->Packet() != current_packet )
		internal_error("Mismatch: last_slot->packet != current_packet");

	if ( packets_on_hold.empty() ||
	     packets_on_hold.back() != current_packet )
		internal_error("Mismatch: packets_on_hold.back() != current_packet");

	int is_orig = current_packet->IsOrig() ? 1 : 0;

	if ( current_packet->SeqGap() > 0 )
		// This packet signals a sequence gap (on the opposite flow).
		answered[is_orig] = 0;

	// Is the current packet an empty placeholder packet?
	int current_packet_is_empty =
		last_slot->isEmpty() &&
		current_packet->SeqLength() == 0 &&
		! current_packet->GetTCP_Flag(TH_SYN|TH_RST|TH_FIN|TH_URG) &&
		! current_packet->HasReservedSlot();

	if ( current_packet_is_empty )
		{
		if ( answered[is_orig] )
			{
// #define DO_NOT_CLEAN_UP_ONLY_PREDICT
#ifdef DO_NOT_CLEAN_UP_ONLY_PREDICT
			// for debugging
			current_packet->PredictAsEmptyPlaceHolder();
#else
			++num_packets_cleaned;
			packets_on_hold.pop_back();
			Unref(current_packet);
			current_packet = 0;
			slot_queue.pop_back();
			delete last_slot;
			last_slot = slot_queue.back();
#endif
			}
		}
	else
		// Current packet may not be empty ...
		answered[1 - is_orig] = 0;

	answered[is_orig] = 1;
	}

int TCP_Rewriter::LeaveAddrInTheClear(int is_orig)
	{
	if ( packets_rewritten > 0 )
		return 0;

	if ( is_orig )
		anon_addr[0] = to_v4_addr(analyzer->Conn()->OrigAddr());
	else
		anon_addr[1] = to_v4_addr(analyzer->Conn()->RespAddr());

	return 1;
	}

TCP_Endpoint* TCP_Rewriter::GetEndpoint(TCP_RewriterEndpoint* endp)
	{
	if ( endp == orig )
		return analyzer->Orig();
	else
		return analyzer->Resp();
	}

TCP_RewriterEndpoint* TCP_Rewriter::GetPeer(TCP_RewriterEndpoint* endp)
	{
	if ( endp == orig )
		return resp;

	else if ( endp == resp )
		return orig;

	else
		return 0;
	}

#define KEEP_ORIG	1
#define REUSE_OPT	1
#define TO_NOP		0
#define MAX_TCP_OPTION_REWRITING	9

struct TCPOptionRewriting {
	int keep_orig;
	int reuse;
} tcp_option_rewriting[MAX_TCP_OPTION_REWRITING] = {
	//  0        -    End of Option List                 [RFC793]
	{KEEP_ORIG, REUSE_OPT},

	//  1        -    No-Operation                       [RFC793]
	{KEEP_ORIG, REUSE_OPT},

	//  2        4    Maximum Segment Size               [RFC793]
	{KEEP_ORIG, REUSE_OPT},

	//  3        3    WSOPT - Window Scale              [RFC1323]
	{KEEP_ORIG, REUSE_OPT},

	//  4        2    SACK Permitted                    [RFC2018]
	{KEEP_ORIG, REUSE_OPT},

	//  5        N    SACK                              [RFC2018]
	{TO_NOP, TO_NOP},

	//  6        6    Echo (obsoleted by option 8)      [RFC1072]
	{TO_NOP, TO_NOP},

	//  7        6    Echo Reply (obsoleted by option 8)[RFC1072]
	{TO_NOP, TO_NOP},

	//  8       10    TSOPT - Time Stamp Option         [RFC1323]
	{KEEP_ORIG, REUSE_OPT},

	// ** the rest is left for future work **
	//  9        2    Partial Order Connection Permitted[RFC1693]
	// 10        3    Partial Order Service Profile     [RFC1693]
	// 11             CC                                [RFC1644]
	// 12             CC.NEW                            [RFC1644]
	// 13             CC.ECHO                           [RFC1644]
	// 14         3   TCP Alternate Checksum Request    [RFC1146]
	// 15         N   TCP Alternate Checksum Data       [RFC1146]
	// 16             Skeeter                           [Knowles]
	// 17             Bubba                             [Knowles]
	// 18         3   Trailer Checksum Option    [Subbu & Monroe]
	// 19        18   MD5 Signature Option              [RFC2385]
	// 20             SCPS Capabilities                   [Scott]
	// 21		Selective Negative Acknowledgements [Scott]
	// 22		Record Boundaries                   [Scott]
	// 23		Corruption experienced              [Scott]
	// 24		SNAP				 [Sukonnik]
	// 25		Unassigned (released 12/18/00)
	// 26             TCP Compression Filter           [Bellovin]
};

int TCP_Rewriter::RewriteTCPOption(unsigned int opt, unsigned int optlen,
				const u_char* option, TCP_Analyzer* analyzer,
				bool is_orig, void* cookie)
	{
	TCP_TracePacket* p = (TCP_TracePacket*) cookie;

	if ( opt < MAX_TCP_OPTION_REWRITING &&
	     ( (! p->IsReuse() && tcp_option_rewriting[opt].keep_orig) ||
	       (p->IsReuse() && tcp_option_rewriting[opt].reuse) ) )
		// copy/reuse the TCP option
		p->AppendTCPHeader(option, optlen);

	else
		{ // replace it with nop
		static const u_char nop[16] = {
			1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1
		};

		while ( optlen > 0 )
			{
			int k = optlen > 16 ? 16 : optlen;
			p->AppendTCPHeader(nop, k);
			optlen -= k;
			}
		}

	return 0;
	}

TCP_RewriteSlot* TCP_Rewriter::add_slot()
	{
	++highest_slot_number;

	DEBUG_MSG_A("add slot %u\n", highest_slot_number);

	last_slot = current_slot =
		new TCP_RewriteSlot(current_packet, highest_slot_number);

	slot_queue.push_back(current_slot);

	return current_slot;
	}

TCP_RewriteSlot* TCP_Rewriter::find_slot(unsigned int slot)
	{
	// DEBUG_MSG_A("%d slots reserved\n", reserved_slots.size());
	slot_map_t::iterator it = reserved_slots.find(slot);
	if ( it == reserved_slots.end() )
		return 0;

	return it->second;
	}

unsigned int TCP_Rewriter::ReserveSlot()
	{
	if ( ! current_packet )
		{
		run_time("cannot reserve a rewrite slot before packet arrival");
		return 0;
		}

	if ( ! current_slot )
		{
		first_slot = add_slot();
		HoldPacket(current_packet);
		}

	if ( current_slot != last_slot )
		{
		run_time("cannot reserve a slot within a reserved slot");
		return 0;
		}

	int slot_number = current_slot->Number();
	DEBUG_MSG_A("reserved slot %d\n", slot_number);

	reserved_slots[slot_number] = current_slot;
	add_slot();
	current_packet->AddReservedSlot();

	return slot_number;
	}

int TCP_Rewriter::SeekSlot(unsigned int slot)
	{
	TCP_RewriteSlot* s = find_slot(slot);
	if ( ! s )
		return 0;

	current_slot = s;
	return 1;
	}

int TCP_Rewriter::ReturnFromSlot()
	{
	current_slot = last_slot;
	return 1;
	}

int TCP_Rewriter::ReleaseSlot(unsigned int slot)
	{
	slot_map_t::iterator it = reserved_slots.find(slot);
	if ( it == reserved_slots.end() )
		{
		run_time(fmt("cannot find slot %u", slot));
		return 0;
		}

	TCP_RewriteSlot* s = it->second;
	reserved_slots.erase(it);

	if ( s == current_slot )
		ReturnFromSlot();

	DEBUG_MSG_A("release slot %u, slot [%u, %u]\n", s->Number(), first_slot->Number(), last_slot->Number());
	if ( s == first_slot )
		{
		do	// release slots till we get to the next *reserved* slot
			{
			DEBUG_MSG_A("dump slot %d %.6f\n", first_slot->Number(), first_slot->Packet()->TimeStamp());

			first_slot->Dump();
			slot_queue.pop_front();
			delete first_slot;

			if ( slot_queue.empty() )
				{
				first_slot = last_slot = current_slot = 0;
				DEBUG_MSG_A("release all packets on hold\n");
				ReleasePacketsOnHold();
				break;
				}

			first_slot = slot_queue.front();
			HoldPacket(first_slot->Packet());
			DEBUG_MSG_A("move on to packet %d (%.6f)\n", first_slot->Packet()->PacketSeq(), first_slot->Packet()->TimeStamp());
			}
		while ( ! find_slot(first_slot->Number()) );
		}

	return 1;
	}

TCP_RewriteSlot::TCP_RewriteSlot(TCP_TracePacket* p, unsigned int number)
	{
	packet = p;
	slot_number = number;
	rewriter = packet->TraceRewriter();
	}

void TCP_RewriteSlot::WriteData(int is_orig, int len, const u_char* data)
	{
	if ( is_orig != packet->IsOrig() )
		{
		run_time("writing data to a slot of wrong direction %s",
			rewriter->analyzer->Conn());

		BroString* tmp = new BroString(data, len, 1);
		char* tmp_s = tmp->Render();
		run_time(fmt("further info: dir = %s, len = %d, data = \"%s\"",
				is_orig ? "orig" : "resp", len, tmp_s));
		delete tmp_s;
		delete tmp;
		return;
		}

	BroString* s = new BroString((const u_char*) data, len, 1);
	buf.push(s);
	}

void TCP_RewriteSlot::Dump()
	{
	while ( ! buf.empty() )
		{
		BroString* s = buf.front();
		buf.pop();
		DEBUG_MSG_A("dump: \"%s\"\n", s->Bytes());
		rewriter->DoWriteData(packet->IsOrig(), s->Len(), s->Bytes());
		delete s;
		}
	}

static std::queue<TCP_Rewriter*> rewriter_funerals;
static std::queue<TCP_RewriterEndpoint*> rewriters_to_flush;

void schedule_funeral(TCP_Rewriter* rewriter)
	{
	Ref(rewriter->Analyzer()->Conn());
	rewriter_funerals.push(rewriter);
	}

void schedule_flush(TCP_RewriterEndpoint* endp)
	{
	Ref(endp->Analyzer()->Conn());
	rewriters_to_flush.push(endp);
	}

void flush_rewriter_packet()
	{
	while ( ! rewriter_funerals.empty() )
		{
		TCP_Rewriter* rewriter = rewriter_funerals.front();
		rewriter_funerals.pop();
		rewriter->Funeral();
		Unref(rewriter->Analyzer()->Conn());
		}

	while ( ! rewriters_to_flush.empty() )
		{
		TCP_RewriterEndpoint* endp = rewriters_to_flush.front();
		rewriters_to_flush.pop();

		if ( endp )
			{
			endp->Flush();
			Unref(endp->Analyzer()->Conn());
			}
		}

	if ( mgr.HasEvents() )
		internal_error("flushing packets generates additional events!");
	}

TCP_SourcePacket::TCP_SourcePacket(const struct pcap_pkthdr* pcap_hdr, const u_char* pcap_pkt)
	{
	hdr = *pcap_hdr;
	if ( pcap_pkt )
		{
		pkt = new u_char[hdr.caplen];
		memcpy(pkt, pcap_pkt, hdr.caplen);
		}
	else
		{
		hdr.caplen = 0;
		pkt = 0;
		}
	}

TCP_SourcePacket::~TCP_SourcePacket()
	{
	delete [] pkt;
	}

TCP_SourcePacketWriter::TCP_SourcePacketWriter(TCP_Analyzer* analyzer, PacketDumper* arg_dumper)
	{
	dumper = arg_dumper;
	}

TCP_SourcePacketWriter::~TCP_SourcePacketWriter()
	{
	// By default discard all packets of the connection
	// if they are not explicitly dumped.
	Purge(false);
	}

void TCP_SourcePacketWriter::NextPacket(const struct pcap_pkthdr* pcap_hdr,
					const u_char* pcap_pkt)
	{
	source_packets.push(new TCP_SourcePacket(pcap_hdr, pcap_pkt));
	}

void TCP_SourcePacketWriter::Purge(bool dump)
	{
	while ( ! source_packets.empty() )
		{
		TCP_SourcePacket* p = source_packets.front();
		if ( dump )
			dumper->DumpPacket(p->Hdr(), p->Pkt(), p->Len());
		source_packets.pop();
		delete p;
		}
	}

void TCP_SourcePacketWriter::Dump()
	{
	Purge(true);
	}

void TCP_SourcePacketWriter::Abort()
	{
	Purge(false);
	}

TCP_SourcePacketWriter* get_src_pkt_writer(TCP_Analyzer* analyzer)
	{
	if ( ! analyzer || analyzer->Conn()->ConnTransport() != TRANSPORT_TCP )
		internal_error("connection for the trace rewriter does not exist");

	TCP_SourcePacketWriter* writer = analyzer->SourcePacketWriter();
	if ( ! writer )
		{
		if ( ! pkt_dumper )
			return 0;	// don't complain if no output file
		else if ( ! dump_selected_source_packets )
			builtin_run_time("flag dump_source_packets is not set");
		else
			internal_error("source packet writer not initialized");
		}

	return writer;
	}


#include "common-rw.bif.func_def"
