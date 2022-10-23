#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

#include <algorithm>

#include "zeek/File.h"
#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"
#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

namespace zeek::analyzer::tcp
	{

// Note, sequence numbers are relative. I.e., they start with 1.

constexpr bool DEBUG_tcp_contents = false;
constexpr bool DEBUG_tcp_connection_close = false;
constexpr bool DEBUG_tcp_match_undelivered = false;

TCP_Reassembler::TCP_Reassembler(analyzer::Analyzer* arg_dst_analyzer,
                                 packet_analysis::TCP::TCPSessionAdapter* arg_tcp_analyzer,
                                 TCP_Reassembler::Type arg_type, TCP_Endpoint* arg_endp)
	: Reassembler(1, REASSEM_TCP)
	{
	dst_analyzer = arg_dst_analyzer;
	tcp_analyzer = arg_tcp_analyzer;
	type = arg_type;
	endp = arg_endp;
	had_gap = false;
	deliver_tcp_contents = false;
	skip_deliveries = false;
	did_EOF = false;
	seq_to_skip = 0;
	in_delivery = false;

	if ( zeek::detail::tcp_max_old_segments )
		SetMaxOldBlocks(zeek::detail::tcp_max_old_segments);

	if ( ::tcp_contents )
		{
		static auto tcp_content_delivery_ports_orig = id::find_val<TableVal>(
			"tcp_content_delivery_ports_orig");
		static auto tcp_content_delivery_ports_resp = id::find_val<TableVal>(
			"tcp_content_delivery_ports_resp");
		const auto& dst_port_val = val_mgr->Port(ntohs(tcp_analyzer->Conn()->RespPort()),
		                                         TRANSPORT_TCP);
		const auto& ports = IsOrig() ? tcp_content_delivery_ports_orig
		                             : tcp_content_delivery_ports_resp;
		auto result = ports->FindOrDefault(dst_port_val);

		if ( (IsOrig() && zeek::detail::tcp_content_deliver_all_orig) ||
		     (! IsOrig() && zeek::detail::tcp_content_deliver_all_resp) ||
		     (result && result->AsBool()) )
			deliver_tcp_contents = true;
		}
	}

void TCP_Reassembler::Done()
	{
	MatchUndelivered(-1, true);

	if ( record_contents_file )
		{ // Record any undelivered data.
		if ( ! block_list.Empty() )
			{
			const auto& last_block = block_list.LastBlock();

			if ( last_reassem_seq < last_block.upper )
				RecordToSeq(last_reassem_seq, last_block.upper, record_contents_file);
			}

		record_contents_file->Close();
		}
	}

void TCP_Reassembler::SizeBufferedData(uint64_t& waiting_on_hole, uint64_t& waiting_on_ack) const
	{
	waiting_on_hole = waiting_on_ack = 0;
	block_list.DataSize(last_reassem_seq, &waiting_on_ack, &waiting_on_hole);
	}

uint64_t TCP_Reassembler::NumUndeliveredBytes() const
	{
	if ( block_list.Empty() )
		return 0;

	const auto& last_block = block_list.LastBlock();
	return last_block.upper - last_reassem_seq;
	}

void TCP_Reassembler::SetContentsFile(FilePtr f)
	{
	if ( ! f->IsOpen() )
		{
		reporter->Error("no such file \"%s\"", f->Name());
		return;
		}

	if ( record_contents_file )
		{
		// We were already recording, no need to catch up.
		record_contents_file = nullptr;
		}
	else
		{
		if ( ! block_list.Empty() )
			RecordToSeq(block_list.Begin()->second.seq, last_reassem_seq, f);
		}

	record_contents_file = std::move(f);
	}

static inline bool is_clean(const TCP_Endpoint* a)
	{
	return a->state == TCP_ENDPOINT_ESTABLISHED ||
	       (a->state == TCP_ENDPOINT_CLOSED && a->prev_state == TCP_ENDPOINT_ESTABLISHED);
	}

static inline bool established_or_cleanly_closing(const TCP_Endpoint* a, const TCP_Endpoint* b)
	{
	return is_clean(a) && is_clean(b);
	}

static inline bool report_gap(const TCP_Endpoint* a, const TCP_Endpoint* b)
	{
	return content_gap &&
	       (BifConst::report_gaps_for_partial || established_or_cleanly_closing(a, b));
	}

void TCP_Reassembler::Gap(uint64_t seq, uint64_t len)
	{
	// Only report on content gaps for connections that
	// are in a cleanly established or closing  state. In
	// other states, these can arise falsely due to things
	// like sequence number mismatches in RSTs, or
	// unseen previous packets in partial connections.

	if ( established_or_cleanly_closing(endp, endp->peer) )
		endp->Gap(seq, len);

	if ( report_gap(endp, endp->peer) )
		dst_analyzer->EnqueueConnEvent(content_gap, dst_analyzer->ConnVal(),
		                               val_mgr->Bool(IsOrig()), val_mgr->Count(seq),
		                               val_mgr->Count(len));

	if ( type == Direct )
		dst_analyzer->NextUndelivered(seq, len, IsOrig());
	else
		dst_analyzer->ForwardUndelivered(seq, len, IsOrig());

	had_gap = true;
	}

void TCP_Reassembler::Undelivered(uint64_t up_to_seq)
	{
	TCP_Endpoint* endpoint = endp;
	TCP_Endpoint* peer = endpoint->peer;

	if ( up_to_seq <= 2 && tcp_analyzer->IsPartial() )
		{
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
		DEBUG_MSG("%.6f Undelivered: IsOrig()=%d up_to_seq=%" PRIu64 ", last_reassm=%" PRIu64 ", "
		          "endp: FIN_cnt=%d, RST_cnt=%d, "
		          "peer: FIN_cnt=%d, RST_cnt=%d\n",
		          zeek::run_state::network_time, IsOrig(), up_to_seq, last_reassem_seq,
		          endpoint->FIN_cnt, endpoint->RST_cnt, peer->FIN_cnt, peer->RST_cnt);
		}

	if ( up_to_seq <= last_reassem_seq )
		// This should never happen. (Reassembler::TrimToSeq has the only call
		// to this method and only if this condition is not true).
		reporter->InternalError("Calling Undelivered for data that has already been delivered (or "
		                        "has already been marked as undelivered");

	if ( BifConst::detect_filtered_trace && last_reassem_seq == 1 &&
	     (endpoint->FIN_cnt > 0 || endpoint->RST_cnt > 0 || peer->FIN_cnt > 0 ||
	      peer->RST_cnt > 0) )
		{
		// We could be running on a SYN/FIN/RST-filtered trace - don't
		// complain about data missing at the end of the connection.
		//
		// ### However, note that the preceding test is not a precise
		// one for filtered traces, and may fail, for example, when
		// the SYN packet carries data.
		//
		// Skip the undelivered part without reporting to the endpoint.
		skip_deliveries = true;
		}
	else
		{
		if ( DEBUG_tcp_contents )
			{
			DEBUG_MSG("%.6f Undelivered: IsOrig()=%d, seq=%" PRIu64 ", len=%" PRIu64 ", "
			          "skip_deliveries=%d\n",
			          run_state::network_time, IsOrig(), last_reassem_seq,
			          up_to_seq - last_reassem_seq, skip_deliveries);
			}

		if ( ! skip_deliveries )
			{
			// If we have blocks that begin below up_to_seq, deliver them.
			auto it = block_list.Begin();

			while ( it != block_list.End() )
				{
				const auto& b = it->second;

				if ( b.seq < last_reassem_seq )
					{
					// Already delivered this block.
					++it;
					continue;
					}

				if ( b.seq >= up_to_seq )
					// Block is beyond what we need to process at this point.
					break;

				uint64_t gap_at_seq = last_reassem_seq;
				uint64_t gap_len = b.seq - last_reassem_seq;

				Gap(gap_at_seq, gap_len);
				last_reassem_seq += gap_len;
				BlockInserted(it);
				// Inserting a block may cause trimming of what's buffered,
				// so have to assume 'b' is invalid, hence re-assign to start.
				it = block_list.Begin();
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

	if ( zeek::detail::tcp_match_undelivered )
		MatchUndelivered(up_to_seq, false);

	// But we need to re-adjust last_reassem_seq in either case.
	if ( up_to_seq > last_reassem_seq )
		last_reassem_seq = up_to_seq; // we've done our best ...
	}

void TCP_Reassembler::MatchUndelivered(uint64_t up_to_seq, bool use_last_upper)
	{
	if ( block_list.Empty() || ! zeek::detail::rule_matcher )
		return;

	const auto& last_block = block_list.LastBlock();

	if ( use_last_upper )
		up_to_seq = last_block.upper;

	// ### Note: the original code did not check whether blocks have
	// already been delivered, but not ACK'ed, and therefore still
	// must be kept in the reassember.

	// We are to match any undelivered data, from last_reassem_seq to
	// min(last_block->upper, up_to_seq).
	// Is there such data?
	if ( up_to_seq <= last_reassem_seq || last_block.upper <= last_reassem_seq )
		return;

	// Skip blocks that are already delivered (but not ACK'ed).
	// Question: shall we instead keep a pointer to the first undelivered
	// block?

	for ( auto it = block_list.Begin(); it != block_list.End(); ++it )
		{
		const auto& b = it->second;

		if ( b.upper > last_reassem_seq )
			break;

		tcp_analyzer->Conn()->Match(zeek::detail::Rule::PAYLOAD, b.block, b.Size(), false, false,
		                            IsOrig(), false);
		}
	}

void TCP_Reassembler::RecordToSeq(uint64_t start_seq, uint64_t stop_seq, const FilePtr& f)
	{
	auto it = block_list.Begin();

	// Skip over blocks up to the start seq.
	while ( it != block_list.End() && it->second.upper <= start_seq )
		++it;

	if ( it == block_list.End() )
		return;

	uint64_t last_seq = start_seq;

	while ( it != block_list.End() && it->second.upper <= stop_seq )
		{
		const auto& b = it->second;

		if ( b.seq > last_seq )
			RecordGap(last_seq, b.seq, f);

		RecordBlock(b, f);
		last_seq = b.upper;
		++it;
		}

	if ( it != block_list.End() )
		// Check for final gap.
		if ( last_seq < stop_seq )
			RecordGap(last_seq, stop_seq, f);
	}

void TCP_Reassembler::RecordBlock(const DataBlock& b, const FilePtr& f)
	{
	if ( f->Write((const char*)b.block, b.Size()) )
		return;

	reporter->Error("TCP_Reassembler contents write failed");

	if ( contents_file_write_failure )
		tcp_analyzer->EnqueueConnEvent(
			contents_file_write_failure, Endpoint()->Conn()->GetVal(), val_mgr->Bool(IsOrig()),
			make_intrusive<StringVal>("TCP reassembler content write failure"));
	}

void TCP_Reassembler::RecordGap(uint64_t start_seq, uint64_t upper_seq, const FilePtr& f)
	{
	if ( f->Write(util::fmt("\n<<gap %" PRIu64 ">>\n", upper_seq - start_seq)) )
		return;

	reporter->Error("TCP_Reassembler contents gap write failed");

	if ( contents_file_write_failure )
		tcp_analyzer->EnqueueConnEvent(
			contents_file_write_failure, Endpoint()->Conn()->GetVal(), val_mgr->Bool(IsOrig()),
			make_intrusive<StringVal>("TCP reassembler gap write failure"));
	}

void TCP_Reassembler::BlockInserted(DataBlockMap::const_iterator it)
	{
	const auto& start_block = it->second;

	if ( start_block.seq > last_reassem_seq || start_block.upper <= last_reassem_seq )
		return;

	// We've filled a leading hole.  Deliver as much as possible.
	// Note that the new block may include both some old stuff
	// and some new stuff.  AddAndCheck() will have split the
	// new stuff off into its own block(s), but in the following
	// loop we have to take care not to deliver already-delivered
	// data.
	while ( it != block_list.End() )
		{
		const auto& b = it->second;

		if ( b.seq > last_reassem_seq )
			break;

		if ( b.seq == last_reassem_seq )
			{ // New stuff.
			uint64_t len = b.Size();
			uint64_t seq = last_reassem_seq;
			last_reassem_seq += len;

			if ( record_contents_file )
				RecordBlock(b, record_contents_file);

			DeliverBlock(seq, len, b.block);
			}

		++it;
		}

	TCP_Endpoint* e = endp;

	if ( ! e->peer->HasContents() )
		// Our endpoint's peer doesn't do reassembly and so
		// (presumably) isn't processing acks.  So don't hold
		// the now-delivered data.
		TrimToSeq(last_reassem_seq);

	else if ( e->NoDataAcked() && zeek::detail::tcp_max_initial_window &&
	          e->Size() > static_cast<uint64_t>(zeek::detail::tcp_max_initial_window) )
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

void TCP_Reassembler::Overlap(const u_char* b1, const u_char* b2, uint64_t n)
	{
	if ( DEBUG_tcp_contents )
		DEBUG_MSG("%.6f TCP contents overlap: %" PRIu64 " IsOrig()=%d\n", run_state::network_time,
		          n, IsOrig());

	if ( rexmit_inconsistency && memcmp((const void*)b1, (const void*)b2, n) &&
	     // The following weeds out keep-alives for which that's all
	     // we've ever seen for the connection.
	     (n > 1 || endp->peer->HasDoneSomething()) )
		{
		String* b1_s = new String((const u_char*)b1, n, false);
		String* b2_s = new String((const u_char*)b2, n, false);

		tcp_analyzer->EnqueueConnEvent(
			rexmit_inconsistency, tcp_analyzer->ConnVal(), make_intrusive<StringVal>(b1_s),
			make_intrusive<StringVal>(b2_s), make_intrusive<StringVal>(flags.AsString()));
		}
	}

void TCP_Reassembler::Deliver(uint64_t seq, int len, const u_char* data)
	{
	if ( type == Direct )
		dst_analyzer->NextStream(len, data, IsOrig());
	else
		dst_analyzer->ForwardStream(len, data, IsOrig());
	}

bool TCP_Reassembler::DataSent(double t, uint64_t seq, int len, const u_char* data,
                               TCP_Flags arg_flags, bool replaying)
	{
	uint64_t ack = endp->ToRelativeSeqSpace(endp->AckSeq(), endp->AckWraps());
	uint64_t upper_seq = seq + len;

	if ( DEBUG_tcp_contents )
		{
		DEBUG_MSG("%.6f DataSent: IsOrig()=%d seq=%" PRIu64 " upper=%" PRIu64 " ack=%" PRIu64 "\n",
		          run_state::network_time, IsOrig(), seq, upper_seq, ack);
		}

	if ( skip_deliveries )
		return false;

	if ( seq < ack && ! replaying )
		{
		if ( upper_seq <= ack )
			// We've already delivered this and it's been acked.
			return false;

		// We've seen an ack for part of this packet, but not the
		// whole thing.  This can happen when, for example, a previous
		// packet held [a, a+b) and this packet holds [a, a+c) for c>b
		// (which some TCP's will do when retransmitting).  Trim the
		// packet to just the unacked data.
		uint64_t amount_acked = ack - seq;
		seq += amount_acked;
		data += amount_acked;
		len -= amount_acked;
		}

	flags = arg_flags;
	NewBlock(t, seq, len, data);
	flags = TCP_Flags();

	if ( Endpoint()->NoDataAcked() && zeek::detail::tcp_max_above_hole_without_any_acks &&
	     NumUndeliveredBytes() >
	         static_cast<uint64_t>(zeek::detail::tcp_max_above_hole_without_any_acks) )
		{
		tcp_analyzer->Weird("above_hole_data_without_any_acks");
		ClearBlocks();
		skip_deliveries = true;
		}

	if ( zeek::detail::tcp_excessive_data_without_further_acks &&
	     block_list.DataSize() >
	         static_cast<uint64_t>(zeek::detail::tcp_excessive_data_without_further_acks) )
		{
		tcp_analyzer->Weird("excessive_data_without_further_acks");
		ClearBlocks();
		skip_deliveries = true;
		}

	return true;
	}

void TCP_Reassembler::AckReceived(uint64_t seq)
	{
	if ( endp->FIN_cnt > 0 && seq >= endp->FIN_seq )
		seq = endp->FIN_seq - 1;

	if ( seq <= trim_seq )
		// Nothing to do.
		return;

	bool test_active = ! skip_deliveries && ! tcp_analyzer->Skipping() &&
	                   (BifConst::report_gaps_for_partial ||
	                    (endp->state == TCP_ENDPOINT_ESTABLISHED &&
	                     endp->peer->state == TCP_ENDPOINT_ESTABLISHED));

	uint64_t num_missing = TrimToSeq(seq);

	if ( test_active )
		{
		++zeek::detail::tot_ack_events;
		zeek::detail::tot_ack_bytes += seq - trim_seq;

		if ( num_missing > 0 )
			{
			++zeek::detail::tot_gap_events;
			zeek::detail::tot_gap_bytes += num_missing;
			}
		}

	// Check EOF here because t_reassem->LastReassemSeq() may have
	// changed after calling TrimToSeq().
	CheckEOF();
	}

void TCP_Reassembler::CheckEOF()
	{
	// It is important that the check on whether we have pending data here
	// is consistent with the check in TCP_Connection::ConnectionClosed().
	//
	// If we choose to call EndpointEOF here because, for example, we
	// are already skipping deliveries, ConnectionClosed() might decide
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
			DEBUG_MSG("%.6f EOF for %d\n", run_state::network_time, endp->IsOrig());
			}

		did_EOF = true;
		tcp_analyzer->EndpointEOF(this);
		}
	}

// DeliverBlock is basically a relay to function Deliver. But unlike
// Deliver, DeliverBlock is not virtual, and this allows us to insert
// operations that apply to all connections using TCP_Contents.

void TCP_Reassembler::DeliverBlock(uint64_t seq, int len, const u_char* data)
	{
	if ( seq + len <= seq_to_skip )
		return;

	if ( seq < seq_to_skip )
		{
		uint64_t to_skip = seq_to_skip - seq;
		len -= to_skip;
		data += to_skip;
		seq = seq_to_skip;
		}

	if ( deliver_tcp_contents )
		tcp_analyzer->EnqueueConnEvent(tcp_contents, tcp_analyzer->ConnVal(),
		                               val_mgr->Bool(IsOrig()), val_mgr->Count(seq),
		                               make_intrusive<StringVal>(len, (const char*)data));

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

void TCP_Reassembler::SkipToSeq(uint64_t seq)
	{
	if ( seq > seq_to_skip )
		{
		seq_to_skip = seq;
		if ( ! in_delivery )
			TrimToSeq(seq);
		}
	}

bool TCP_Reassembler::DataPending() const
	{
	// If we are skipping deliveries, the reassembler will not get called
	// in DataSent(), and DataSeq() will not be updated.
	if ( skip_deliveries )
		return false;

	uint64_t delivered_seq = Endpoint()->StartSeqI64() + DataSeq();
	uint64_t last_seq = TCP_Endpoint::ToFullSeqSpace(Endpoint()->LastSeq(), Endpoint()->SeqWraps());

	if ( last_seq < delivered_seq )
		return false;

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
	if ( delivered_seq != last_seq - 1 && delivered_seq != last_seq )
		return true;

	// If we've sent RST, then we can't send ACKs any more.
	if ( Endpoint()->state != TCP_ENDPOINT_RESET && Endpoint()->peer->HasUndeliveredData() )
		return true;

	return false;
	}

	} // namespace zeek::analyzer::tcp
