#include <algorithm>

#include "analyzer/Analyzer.h"
#include "TCP_Reassembler.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "TCP_Endpoint.h"

// Only needed for gap_report events.
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::tcp;

// Note, sequence numbers are relative. I.e., they start with 1.

const bool DEBUG_tcp_contents = false;
const bool DEBUG_tcp_connection_close = false;
const bool DEBUG_tcp_match_undelivered = false;

static double last_gap_report = 0.0;
static uint64 last_ack_events = 0;
static uint64 last_ack_bytes = 0;
static uint64 last_gap_events = 0;
static uint64 last_gap_bytes = 0;

TCP_Reassembler::TCP_Reassembler(analyzer::Analyzer* arg_dst_analyzer,
				TCP_Analyzer* arg_tcp_analyzer,
				TCP_Reassembler::Type arg_type,
				TCP_Endpoint* arg_endp)
	: Reassembler(1)
	{
	dst_analyzer = arg_dst_analyzer;
	tcp_analyzer = arg_tcp_analyzer;
	type = arg_type;
	endp = arg_endp;
	had_gap = false;
	record_contents_file = 0;
	deliver_tcp_contents = 0;
	skip_deliveries = 0;
	did_EOF = 0;
	seq_to_skip = 0;
	in_delivery = false;

	if ( tcp_max_old_segments )
		SetMaxOldBlocks(tcp_max_old_segments);

	if ( tcp_contents )
		{
		// Val dst_port_val(ntohs(Conn()->RespPort()), TYPE_PORT);
		PortVal dst_port_val(ntohs(tcp_analyzer->Conn()->RespPort()),
					TRANSPORT_TCP);
		TableVal* ports = IsOrig() ?
			tcp_content_delivery_ports_orig :
			tcp_content_delivery_ports_resp;
		Val* result = ports->Lookup(&dst_port_val);

		if ( (IsOrig() && tcp_content_deliver_all_orig) ||
		     (! IsOrig() && tcp_content_deliver_all_resp) ||
		     (result && result->AsBool()) )
			deliver_tcp_contents = 1;
		}
	}

TCP_Reassembler::~TCP_Reassembler()
	{
	Unref(record_contents_file);
	}

void TCP_Reassembler::Done()
	{
	MatchUndelivered(-1, true);

	if ( record_contents_file )
		{ // Record any undelivered data.
		if ( blocks && last_reassem_seq < last_block->upper )
			RecordToSeq(last_reassem_seq, last_block->upper,
					record_contents_file);

		record_contents_file->Close();
		}
	}

void TCP_Reassembler::SizeBufferedData(uint64& waiting_on_hole,
					uint64& waiting_on_ack) const
	{
	waiting_on_hole = waiting_on_ack = 0;
	for ( DataBlock* b = blocks; b; b = b->next )
		{
		if ( b->seq <= last_reassem_seq )
			// We must have delivered this block, but
			// haven't yet trimmed it.
			waiting_on_ack += b->Size();
		else
			waiting_on_hole += b->Size();
		}
	}

void TCP_Reassembler::SetContentsFile(BroFile* f)
	{
	if ( ! f->IsOpen() )
		{
		reporter->Error("no such file \"%s\"", f->Name());
		return;
		}

	if ( record_contents_file )
		// We were already recording, no need to catch up.
		Unref(record_contents_file);
	else
		{
		if ( blocks )
			RecordToSeq(blocks->seq, last_reassem_seq, f);
		}

	// Don't want rotation on these files.
	f->SetRotateInterval(0);

	Ref(f);
	record_contents_file = f;
	}

static inline bool established(const TCP_Endpoint* a, const TCP_Endpoint* b)
	{
	return a->state == TCP_ENDPOINT_ESTABLISHED &&
	       b->state == TCP_ENDPOINT_ESTABLISHED;
	}

static inline bool report_gap(const TCP_Endpoint* a, const TCP_Endpoint* b)
	{
	return content_gap &&
	       ( BifConst::report_gaps_for_partial || established(a, b) );
	}

void TCP_Reassembler::Gap(uint64 seq, uint64 len)
	{
	// Only report on content gaps for connections that
	// are in a cleanly established state.  In other
	// states, these can arise falsely due to things
	// like sequence number mismatches in RSTs, or
	// unseen previous packets in partial connections.
	// The one opportunity we lose here is on clean FIN
	// handshakes, but Oh Well.

	if ( report_gap(endp, endp->peer) )
		{
		val_list* vl = new val_list;
		vl->append(dst_analyzer->BuildConnVal());
		vl->append(new Val(IsOrig(), TYPE_BOOL));
		vl->append(new Val(seq, TYPE_COUNT));
		vl->append(new Val(len, TYPE_COUNT));
		dst_analyzer->ConnectionEvent(content_gap, vl);
		}

	if ( type == Direct )
		dst_analyzer->NextUndelivered(seq, len, IsOrig());
	else
		dst_analyzer->ForwardUndelivered(seq, len, IsOrig());

	had_gap = true;
	}

void TCP_Reassembler::Undelivered(uint64 up_to_seq)
	{
	TCP_Endpoint* endpoint = endp;
	TCP_Endpoint* peer = endpoint->peer;

	if ( up_to_seq <= 2 && tcp_analyzer->IsPartial() ) {
		// Since it was a partial connection, we faked up its
		// initial sequence numbers as though we'd seen a SYN.
		// We've now received the first ack and are getting a
		// complaint that either that data is missing (if
		// up_to_seq is 1), or one octet beyond it is missing
		// (if up_to_seq is 2).  The latter can occur when the
		// first packet we saw instantiating the partial connection
		// was a keep-alive.  So, in either case, just ignore it.

		// TODO: Don't we need to update last_reassm_seq ????
		return;
	}

#if 0
	if ( endpoint->FIN_cnt > 0 )
		{
		// Make sure we're not worrying about undelivered
		// FIN control octets!
		if ( up_to_seq >= endpoint->FIN_seq )
			up_to_seq = endpoint->FIN_seq - 1;
		}
#endif

	if ( DEBUG_tcp_contents )
		{
		DEBUG_MSG("%.6f Undelivered: IsOrig()=%d up_to_seq=%" PRIu64", last_reassm=%" PRIu64", "
		          "endp: FIN_cnt=%d, RST_cnt=%d, "
		          "peer: FIN_cnt=%d, RST_cnt=%d\n",
		          network_time, IsOrig(), up_to_seq, last_reassem_seq,
		          endpoint->FIN_cnt, endpoint->RST_cnt,
		          peer->FIN_cnt, peer->RST_cnt);
		}

	if ( up_to_seq <= last_reassem_seq )
		// This should never happen. (Reassembler::TrimToSeq has the only call
		// to this method and only if this condition is not true).
		reporter->InternalError("Calling Undelivered for data that has already been delivered (or has already been marked as undelivered");

	if ( BifConst::detect_filtered_trace && last_reassem_seq == 1 &&
	     (endpoint->FIN_cnt > 0 || endpoint->RST_cnt > 0 ||
	      peer->FIN_cnt > 0 || peer->RST_cnt > 0) )
		{
		// We could be running on a SYN/FIN/RST-filtered trace - don't
		// complain about data missing at the end of the connection.
		//
		// ### However, note that the preceding test is not a precise
		// one for filtered traces, and may fail, for example, when
		// the SYN packet carries data.
		//
		// Skip the undelivered part without reporting to the endpoint.
		skip_deliveries = 1;
		}
	else
		{
		if ( DEBUG_tcp_contents )
			{
			DEBUG_MSG("%.6f Undelivered: IsOrig()=%d, seq=%" PRIu64", len=%" PRIu64", "
					  "skip_deliveries=%d\n",
					  network_time, IsOrig(), last_reassem_seq,
					  up_to_seq - last_reassem_seq,
					  skip_deliveries);
			}

		if ( ! skip_deliveries )
			{
			// If we have blocks that begin below up_to_seq, deliver them.
			DataBlock* b = blocks;
			while ( b )
				{
				if ( b->seq < last_reassem_seq )
					{
					// Already delivered this block.
					b = b->next;
					continue;
					}

				if ( b->seq >= up_to_seq )
					// Block is beyond what we need to process at this point.
					break;

				uint64 gap_at_seq = last_reassem_seq;
				uint64 gap_len = b->seq - last_reassem_seq;

				Gap(gap_at_seq, gap_len);
				last_reassem_seq += gap_len;
				BlockInserted(b);
				// Inserting a block may cause trimming of what's buffered,
				// so have to assume 'b' is invalid, hence re-assign to start.
				b = blocks;
				}

			if ( up_to_seq > last_reassem_seq )
				Gap(last_reassem_seq, up_to_seq - last_reassem_seq);
			}
		}

	// We should record and match undelivered even if we are skipping
	// content gaps between SYN and FIN, because FIN may carry some data.
	//
	if ( record_contents_file )
		RecordToSeq(last_reassem_seq, up_to_seq, record_contents_file);

	if ( tcp_match_undelivered )
		MatchUndelivered(up_to_seq, false);

	// But we need to re-adjust last_reassem_seq in either case.
	if ( up_to_seq > last_reassem_seq )
		last_reassem_seq = up_to_seq;	// we've done our best ...
	}

void TCP_Reassembler::MatchUndelivered(uint64 up_to_seq, bool use_last_upper)
	{
	if ( ! blocks || ! rule_matcher )
		return;

	ASSERT(last_block);
	if ( use_last_upper )
		up_to_seq = last_block->upper;

	// ### Note: the original code did not check whether blocks have
	// already been delivered, but not ACK'ed, and therefore still
	// must be kept in the reassember.

	// We are to match any undelivered data, from last_reassem_seq to
	// min(last_block->upper, up_to_seq).
	// Is there such data?
	if ( up_to_seq <= last_reassem_seq ||
	     last_block->upper <= last_reassem_seq )
		return;

	// Skip blocks that are already delivered (but not ACK'ed).
	// Question: shall we instead keep a pointer to the first undelivered
	// block?
	DataBlock* b;
	for ( b = blocks; b && b->upper <= last_reassem_seq; b = b->next )
	      tcp_analyzer->Conn()->Match(Rule::PAYLOAD, b->block, b->Size(),
						false, false, IsOrig(), false);

	ASSERT(b);
	}

void TCP_Reassembler::RecordToSeq(uint64 start_seq, uint64 stop_seq, BroFile* f)
	{
	DataBlock* b = blocks;
	// Skip over blocks up to the start seq.
	while ( b && b->upper <= start_seq )
		b = b->next;

	if ( ! b )
		return;

	uint64 last_seq = start_seq;
	while ( b && b->upper <= stop_seq )
		{
		if ( b->seq > last_seq )
			RecordGap(last_seq, b->seq, f);

		RecordBlock(b, f);
		last_seq = b->upper;
		b = b->next;
		}

	if ( b )
		// Check for final gap.
		if ( last_seq < stop_seq )
			RecordGap(last_seq, stop_seq, f);
	}

void TCP_Reassembler::RecordBlock(DataBlock* b, BroFile* f)
	{
	if ( f->Write((const char*) b->block, b->Size()) )
		return;

	reporter->Error("TCP_Reassembler contents write failed");

	if ( contents_file_write_failure )
		{
		val_list* vl = new val_list();
		vl->append(Endpoint()->Conn()->BuildConnVal());
		vl->append(new Val(IsOrig(), TYPE_BOOL));
		vl->append(new StringVal("TCP reassembler content write failure"));
		tcp_analyzer->ConnectionEvent(contents_file_write_failure, vl);
		}
	}

void TCP_Reassembler::RecordGap(uint64 start_seq, uint64 upper_seq, BroFile* f)
	{
	if ( f->Write(fmt("\n<<gap %" PRIu64">>\n", upper_seq - start_seq)) )
		return;

	reporter->Error("TCP_Reassembler contents gap write failed");

	if ( contents_file_write_failure )
		{
		val_list* vl = new val_list();
		vl->append(Endpoint()->Conn()->BuildConnVal());
		vl->append(new Val(IsOrig(), TYPE_BOOL));
		vl->append(new StringVal("TCP reassembler gap write failure"));
		tcp_analyzer->ConnectionEvent(contents_file_write_failure, vl);
		}
	}

void TCP_Reassembler::BlockInserted(DataBlock* start_block)
	{
	if ( start_block->seq > last_reassem_seq ||
	     start_block->upper <= last_reassem_seq )
		return;

	// We've filled a leading hole.  Deliver as much as possible.
	// Note that the new block may include both some old stuff
	// and some new stuff.  AddAndCheck() will have split the
	// new stuff off into its own block(s), but in the following
	// loop we have to take care not to deliver already-delivered
	// data.
	for ( DataBlock* b = start_block;
	      b && b->seq <= last_reassem_seq; b = b->next )
		{
		if ( b->seq == last_reassem_seq )
			{ // New stuff.
			uint64 len = b->Size();
			uint64 seq = last_reassem_seq;

			last_reassem_seq += len;

			if ( record_contents_file )
				RecordBlock(b, record_contents_file);

			DeliverBlock(seq, len, b->block);
			}
		}

	TCP_Endpoint* e = endp;

	if ( ! e->peer->HasContents() )
		// Our endpoint's peer doesn't do reassembly and so
		// (presumably) isn't processing acks.  So don't hold
		// the now-delivered data.
		TrimToSeq(last_reassem_seq);

	else if ( e->NoDataAcked() && tcp_max_initial_window &&
		  e->Size() > static_cast<uint64>(tcp_max_initial_window) )
		// We've sent quite a bit of data, yet none of it has
		// been acked.  Presume that we're not seeing the peer's
		// acks (perhaps due to filtering or split routing) and
		// don't hang onto the data further, as we may wind up
		// carrying it all the way until this connection ends.
		TrimToSeq(last_reassem_seq);

	// Note: don't make an EOF check here, because then we'd miss it
	// for FIN packets that don't carry any payload (and thus
	// endpoint->DataSent is not called).  Instead, do the check in
	// TCP_Connection::NextPacket.
	}

void TCP_Reassembler::Overlap(const u_char* b1, const u_char* b2, uint64 n)
	{
	if ( DEBUG_tcp_contents )
		DEBUG_MSG("%.6f TCP contents overlap: %" PRIu64" IsOrig()=%d\n", network_time,  n, IsOrig());

	if ( rexmit_inconsistency &&
	     memcmp((const void*) b1, (const void*) b2, n) &&
	     // The following weeds out keep-alives for which that's all
	     // we've ever seen for the connection.
	     (n > 1 || endp->peer->HasDoneSomething()) )
		{
		BroString* b1_s = new BroString((const u_char*) b1, n, 0);
		BroString* b2_s = new BroString((const u_char*) b2, n, 0);

		val_list* vl = new val_list(3);
		vl->append(tcp_analyzer->BuildConnVal());
		vl->append(new StringVal(b1_s));
		vl->append(new StringVal(b2_s));
		vl->append(new StringVal(flags.AsString()));
		tcp_analyzer->ConnectionEvent(rexmit_inconsistency, vl);
		}
	}

IMPLEMENT_SERIAL(TCP_Reassembler, SER_TCP_REASSEMBLER);

bool TCP_Reassembler::DoSerialize(SerialInfo* info) const
	{
	reporter->InternalError("TCP_Reassembler::DoSerialize not implemented");
	return false; // Cannot be reached.
	}

bool TCP_Reassembler::DoUnserialize(UnserialInfo* info)
	{
	reporter->InternalError("TCP_Reassembler::DoUnserialize not implemented");
	return false; // Cannot be reached.
	}

void TCP_Reassembler::Deliver(uint64 seq, int len, const u_char* data)
	{
	if ( type == Direct )
		dst_analyzer->NextStream(len, data, IsOrig());
	else
		dst_analyzer->ForwardStream(len, data, IsOrig());
	}

int TCP_Reassembler::DataSent(double t, uint64 seq, int len,
				const u_char* data, TCP_Flags arg_flags, bool replaying)
	{
	uint64 ack = endp->ToRelativeSeqSpace(endp->AckSeq(), endp->AckWraps());
	uint64 upper_seq = seq + len;

	if ( DEBUG_tcp_contents )
		{
		DEBUG_MSG("%.6f DataSent: IsOrig()=%d seq=%" PRIu64" upper=%" PRIu64" ack=%" PRIu64"\n",
		          network_time, IsOrig(), seq, upper_seq, ack);
		}

	if ( skip_deliveries )
		return 0;

	if ( seq < ack && ! replaying )
		{
		if ( upper_seq <= ack )
			// We've already delivered this and it's been acked.
			return 0;

		// We've seen an ack for part of this packet, but not the
		// whole thing.  This can happen when, for example, a previous
		// packet held [a, a+b) and this packet holds [a, a+c) for c>b
		// (which some TCP's will do when retransmitting).  Trim the
		// packet to just the unacked data.
		uint64 amount_acked = ack - seq;
		seq += amount_acked;
		data += amount_acked;
		len -= amount_acked;
		}

	flags = arg_flags;
	NewBlock(t, seq, len, data);
	flags = TCP_Flags();

	if ( Endpoint()->NoDataAcked() && tcp_max_above_hole_without_any_acks &&
	     NumUndeliveredBytes() > static_cast<uint64>(tcp_max_above_hole_without_any_acks) )
		{
		tcp_analyzer->Weird("above_hole_data_without_any_acks");
		ClearBlocks();
		skip_deliveries = 1;
		}

	if ( tcp_excessive_data_without_further_acks &&
	     NumUndeliveredBytes() > static_cast<uint64>(tcp_excessive_data_without_further_acks) )
		{
		tcp_analyzer->Weird("excessive_data_without_further_acks");
		ClearBlocks();
		skip_deliveries = 1;
		}

	return 1;
	}


void TCP_Reassembler::AckReceived(uint64 seq)
	{
	if ( endp->FIN_cnt > 0 && seq >= endp->FIN_seq )
		seq = endp->FIN_seq - 1;

	if ( seq <= trim_seq )
		// Nothing to do.
		return;

	bool test_active = ! skip_deliveries && ! tcp_analyzer->Skipping() &&
		( BifConst::report_gaps_for_partial ||
			(endp->state == TCP_ENDPOINT_ESTABLISHED &&
				endp->peer->state == TCP_ENDPOINT_ESTABLISHED ) );

	uint64 num_missing = TrimToSeq(seq);

	if ( test_active )
		{
		++tot_ack_events;
		tot_ack_bytes += seq - trim_seq;

		if ( num_missing > 0 )
			{
			++tot_gap_events;
			tot_gap_bytes += num_missing;
			tcp_analyzer->Event(ack_above_hole);
			}

		double dt = network_time - last_gap_report;

		if ( gap_report && gap_report_freq > 0.0 &&
		     dt >= gap_report_freq )
			{
			uint64 devents = tot_ack_events - last_ack_events;
			uint64 dbytes = tot_ack_bytes - last_ack_bytes;
			uint64 dgaps = tot_gap_events - last_gap_events;
			uint64 dgap_bytes = tot_gap_bytes - last_gap_bytes;

			RecordVal* r = new RecordVal(gap_info);
			r->Assign(0, new Val(devents, TYPE_COUNT));
			r->Assign(1, new Val(dbytes, TYPE_COUNT));
			r->Assign(2, new Val(dgaps, TYPE_COUNT));
			r->Assign(3, new Val(dgap_bytes, TYPE_COUNT));

			val_list* vl = new val_list;
			vl->append(new IntervalVal(dt, Seconds));
			vl->append(r);

			mgr.QueueEvent(gap_report, vl);

			last_gap_report = network_time;
			last_ack_events = tot_ack_events;
			last_ack_bytes = tot_ack_bytes;
			last_gap_events = tot_gap_events;
			last_gap_bytes = tot_gap_bytes;
			}
		}

	// Check EOF here because t_reassem->LastReassemSeq() may have
	// changed after calling TrimToSeq().
	CheckEOF();
	}

void TCP_Reassembler::CheckEOF()
	{
	// It is important that the check on whether we have pending data here
	// is consistent with the check in TCP_Connection::ConnnectionClosed().
	//
	// If we choose to call EndpointEOF here because, for example, we
	// are already skipping deliveries, ConnnectionClosed() might decide
	// that there is still DataPending, because it does not check
	// SkipDeliveries(), and the connection will not be closed until
	// timeout, since the did_EOF flag makes sure that EndpointEOF will
	// be called only once.
	//
	// Now both places call TCP_Reassembler::DataPending(), which checks
	// whether we are skipping deliveries.

	if ( ! did_EOF &&
	     (endp->FIN_cnt > 0 || endp->state == TCP_ENDPOINT_CLOSED ||
	                           endp->state == TCP_ENDPOINT_RESET) &&
	     ! DataPending() )
		{
		// We've now delivered all of the data.
		if ( DEBUG_tcp_connection_close )
			{
			DEBUG_MSG("%.6f EOF for %d\n",
			          network_time, endp->IsOrig());
			}

		did_EOF = 1;
		tcp_analyzer->EndpointEOF(this);
		}
	}

// DeliverBlock is basically a relay to function Deliver. But unlike
// Deliver, DeliverBlock is not virtual, and this allows us to insert
// operations that apply to all connections using TCP_Contents.

void TCP_Reassembler::DeliverBlock(uint64 seq, int len, const u_char* data)
	{
	if ( seq + len <= seq_to_skip )
		return;

	if ( seq < seq_to_skip )
		{
		uint64 to_skip = seq_to_skip - seq;
		len -= to_skip;
		data += to_skip;
		seq = seq_to_skip;
		}

	if ( deliver_tcp_contents )
		{
		val_list* vl = new val_list();
		vl->append(tcp_analyzer->BuildConnVal());
		vl->append(new Val(IsOrig(), TYPE_BOOL));
		vl->append(new Val(seq, TYPE_COUNT));
		vl->append(new StringVal(len, (const char*) data));

		tcp_analyzer->ConnectionEvent(tcp_contents, vl);
		}

	// Q. Can we say this because it is already checked in DataSent()?
	// ASSERT(!Conn()->Skipping() && !SkipDeliveries());
	//
	// A. No, because TrimToSeq() can deliver some blocks after
	// skipping the undelivered.

	if ( skip_deliveries )
		return;

	in_delivery = true;
	Deliver(seq, len, data);
	in_delivery = false;

	if ( seq + len < seq_to_skip )
		SkipToSeq(seq_to_skip);

	}

void TCP_Reassembler::SkipToSeq(uint64 seq)
	{
	if ( seq > seq_to_skip )
		{
		seq_to_skip = seq;
		if ( ! in_delivery )
			TrimToSeq(seq);
		}
	}

int TCP_Reassembler::DataPending() const
	{
	// If we are skipping deliveries, the reassembler will not get called
	// in DataSent(), and DataSeq() will not be updated.
	if ( skip_deliveries )
		return 0;

	uint64 delivered_seq = Endpoint()->StartSeqI64() + DataSeq();
	uint64 last_seq = TCP_Endpoint::ToFullSeqSpace(Endpoint()->LastSeq(),
	                                               Endpoint()->SeqWraps());

	if ( last_seq < delivered_seq )
		return 0;

	// Q. Can we say that?
	// ASSERT(delivered_seq <= last_seq);
	//
	// A. That should be true if endpoints are always initialized w/
	//    trustworthy sequence numbers, though it seems that may not currently
	//    be the case.  e.g. a RST packet may end up initializing the endpoint.
	//    In that case, maybe there's not any "right" way to initialize it, so
	//    the check for last_seq < delivered_seq sort of serves as a check for
	//    endpoints that weren't initialized w/ meaningful sequence numbers.

	// We've delivered everything if we're up to the penultimate
	// sequence number (since a FIN consumes an octet in the
	// sequence space), or right at it (because a RST does not).
	if ( delivered_seq != last_seq - 1 &&
	     delivered_seq != last_seq )
		return 1;

	// If we've sent RST, then we can't send ACKs any more.
	if ( Endpoint()->state != TCP_ENDPOINT_RESET &&
	     Endpoint()->peer->HasUndeliveredData() )
		return 1;

	return 0;
	}
