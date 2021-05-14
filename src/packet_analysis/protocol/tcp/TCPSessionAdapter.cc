// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

#include "zeek/Val.h"
#include "zeek/RunState.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/stepping-stone/SteppingStone.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/analyzer/protocol/tcp/types.bif.h"

static const int ORIG = 1;
static const int RESP = 2;

using namespace zeek;
using namespace zeek::packet_analysis::TCP;

TCPSessionAdapter::TCPSessionAdapter(Connection* conn)
	: packet_analysis::IP::SessionAdapter("TCP", conn)
	{
	// Set a timer to eventually time out this connection.
	ADD_ANALYZER_TIMER(&TCPSessionAdapter::ExpireTimer,
	                   run_state::network_time + detail::tcp_SYN_timeout, false,
	                   detail::TIMER_TCP_EXPIRE);

	deferred_gen_event = close_deferred = 0;

	seen_first_ACK = 0;
	is_active = 1;
	finished = 0;
	reassembling = 0;
	first_packet_seen = 0;
	is_partial = 0;

	orig = new analyzer::tcp::TCP_Endpoint(this, true);
	resp = new analyzer::tcp::TCP_Endpoint(this, false);

	orig->SetPeer(resp);
	resp->SetPeer(orig);
	}

TCPSessionAdapter::~TCPSessionAdapter()
	{
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		delete *i;

	delete orig;
	delete resp;
	}

void TCPSessionAdapter::Init()
	{
	Analyzer::Init();
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		(*i)->Init();
	}

void TCPSessionAdapter::Done()
	{
	Analyzer::Done();

	if ( run_state::terminating && connection_pending && is_active && ! BothClosed() )
		Event(connection_pending);

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		(*i)->Done();

	orig->Done();
	resp->Done();

	finished = 1;
	}

analyzer::Analyzer* TCPSessionAdapter::FindChild(analyzer::ID arg_id)
	{
	analyzer::Analyzer* child = packet_analysis::IP::SessionAdapter::FindChild(arg_id);

	if ( child )
		return child;

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		{
		analyzer::Analyzer* child = (*i)->FindChild(arg_id);
		if ( child )
			return child;
		}

	return nullptr;
	}

analyzer::Analyzer* TCPSessionAdapter::FindChild(analyzer::Tag arg_tag)
	{
	analyzer::Analyzer* child = packet_analysis::IP::SessionAdapter::FindChild(arg_tag);

	if ( child )
		return child;

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		{
		analyzer::Analyzer* child = (*i)->FindChild(arg_tag);
		if ( child )
			return child;
		}

	return nullptr;
	}

bool TCPSessionAdapter::RemoveChildAnalyzer(analyzer::ID id)
	{
	auto rval = packet_analysis::IP::SessionAdapter::RemoveChildAnalyzer(id);

	if ( rval )
		return rval;

	return RemoveChild(packet_children, id);
	}

void TCPSessionAdapter::EnableReassembly()
	{
	SetReassembler(new analyzer::tcp::TCP_Reassembler(
		               this, this, analyzer::tcp::TCP_Reassembler::Forward, orig),
	               new analyzer::tcp::TCP_Reassembler(
		               this, this, analyzer::tcp::TCP_Reassembler::Forward, resp));
	}

void TCPSessionAdapter::SetReassembler(analyzer::tcp::TCP_Reassembler* rorig,
                                       analyzer::tcp::TCP_Reassembler* rresp)
	{
	orig->AddReassembler(rorig);
	rorig->SetDstAnalyzer(this);
	resp->AddReassembler(rresp);
	rresp->SetDstAnalyzer(this);

	if ( new_connection_contents && reassembling == 0 )
		Event(new_connection_contents);

	reassembling = 1;
	}

void TCPSessionAdapter::SetPartialStatus(analyzer::tcp::TCP_Flags flags, bool is_orig)
	{
	if ( is_orig )
		{
		if ( ! (first_packet_seen & ORIG) )
			is_partial = ! flags.SYN() || flags.ACK();
		}
	else
		{
		if ( ! (first_packet_seen & RESP) && ! is_partial )
			is_partial = ! flags.SYN();
		}
	}

void TCPSessionAdapter::UpdateInactiveState(
	double t, analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
	uint32_t base_seq, uint32_t ack_seq,
	int len, bool is_orig, analyzer::tcp::TCP_Flags flags,
	bool& do_close, bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( is_orig )
			{
			if ( flags.ACK() )
				{
				Weird("connection_originator_SYN_ack");
				endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT);
				}
			else
				endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_SYN_SENT);

			if ( zeek::detail::tcp_attempt_delay )
				ADD_ANALYZER_TIMER(&TCPSessionAdapter::AttemptTimer,
				                   t + detail::tcp_attempt_delay, true,
				                   detail::TIMER_TCP_ATTEMPT);
			}
		else
			{
			if ( flags.ACK() )
				{
				if ( peer->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
				     peer->state != analyzer::tcp::TCP_ENDPOINT_PARTIAL &&
				     ! seq_between(ack_seq, peer->StartSeq(), peer->LastSeq()) )
					Weird("bad_SYN_ack");
				}

			else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT &&
				  base_seq == endpoint->StartSeq() )
				{
				// This is a SYN/SYN-ACK reversal,
				// per the discussion in IsReuse.
				// Flip the endpoints and establish
				// the connection.
				is_partial = 0;
				Conn()->FlipRoles();
				peer->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
				}

			else
				Weird("simultaneous_open");

			if ( peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
				peer->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
			else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
				{
				// If we were to ignore SYNs and
				// only instantiate state on SYN
				// acks, then we'd do:
				//    peer->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
				// here.
				Weird("unsolicited_SYN_response");
				}

			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);

			if ( peer->state != analyzer::tcp::TCP_ENDPOINT_PARTIAL )
				{
				Event(connection_established);
				Conn()->EnableStatusUpdateTimer();
				}
			}
		}

	if ( flags.FIN() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);
		do_close = gen_event = true;
		if ( peer->state != analyzer::tcp::TCP_ENDPOINT_PARTIAL && ! flags.SYN() )
			Weird("spontaneous_FIN");
		}

	if ( flags.RST() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);

		bool is_reject = false;

		if ( is_orig )
			{
			// If our peer is established then we saw
			// a SYN-ack but not SYN - so a reverse
			// scan, and we should treat this as a
			// reject.
			if ( peer->state == analyzer::tcp::TCP_ENDPOINT_ESTABLISHED )
				is_reject = true;
			}

		else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT ||
			  peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT )
			// We're rejecting an initial SYN.
			is_reject = true;

		do_close = true;
		gen_event = ! is_reject;

		if ( is_reject )
			Event(connection_rejected);

		else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			Weird("spontaneous_RST");
		}

	if ( endpoint->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
		{ // No control flags to change the state.
		if ( ! is_orig && len == 0 &&
		     orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
			// Some eccentric TCP's will ack an initial
			// SYN prior to sending a SYN reply (hello,
			// ftp.microsoft.com).  For those, don't
			// consider the ack as forming a partial
			// connection.
			;

		else if ( flags.ACK() && peer->state == analyzer::tcp::TCP_ENDPOINT_ESTABLISHED )
			{
			// No SYN packet from originator but SYN/ACK from
			// responder, and now a pure ACK. Problably means we
			// just missed that initial SYN. Let's not treat it
			// as partial and instead establish the connection.
			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
			is_partial = 0;
			}

		else
			{
			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_PARTIAL);
			Conn()->EnableStatusUpdateTimer();

			if ( peer->state == analyzer::tcp::TCP_ENDPOINT_PARTIAL )
				// We've seen both sides of a partial
				// connection, report it.
				Event(partial_connection);
			}
		}
	}

void TCPSessionAdapter::UpdateSYN_SentState(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                                            int len, bool is_orig, analyzer::tcp::TCP_Flags flags,
                                            bool& do_close, bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( is_orig )
			{
			if ( flags.ACK() && ! flags.FIN() && ! flags.RST() &&
			     endpoint->state != analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT )
				Weird("repeated_SYN_with_ack");
			}
		else
			{
			if ( ! flags.ACK() &&
			     endpoint->state != analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
				Weird("repeated_SYN_reply_wo_ack");
			}
		}

	if ( flags.FIN() )
		{
		if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
		     peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
			Weird("inappropriate_FIN");

		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);
		do_close = gen_event = true;
		}

	if ( flags.RST() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);
		ConnectionReset();
		do_close = true;
		}

	else if ( len > 0 )
		Weird("data_before_established");
	}

void TCPSessionAdapter::UpdateEstablishedState(
	analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
	analyzer::tcp::TCP_Flags flags, bool& do_close, bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( endpoint->state == analyzer::tcp::TCP_ENDPOINT_PARTIAL &&
		     peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE && ! flags.ACK() )
			{
			Weird("SYN_after_partial");
			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_SYN_SENT);
			}
		}

	if ( flags.FIN() && ! flags.RST() )	// ###
		{ // should check sequence/ack numbers here ###
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);

		if ( peer->state == analyzer::tcp::TCP_ENDPOINT_RESET &&
		     peer->prev_state == analyzer::tcp::TCP_ENDPOINT_CLOSED )
			// The peer sent a FIN followed by a RST.
			// Turn it back into CLOSED state, because
			// this was actually normal termination.
			peer->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);

		do_close = gen_event = true;
		}

	if ( flags.RST() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);
		do_close = true;

		if ( peer->state != analyzer::tcp::TCP_ENDPOINT_RESET ||
		     peer->prev_state != analyzer::tcp::TCP_ENDPOINT_ESTABLISHED )
			ConnectionReset();
		}
	}

void TCPSessionAdapter::UpdateClosedState(double t, analyzer::tcp::TCP_Endpoint* endpoint,
                                          int32_t delta_last, analyzer::tcp::TCP_Flags flags,
                                          bool& do_close)
	{
	if ( flags.SYN() )
		Weird("SYN_after_close");

	if ( flags.FIN() && delta_last > 0 )
		// Probably should also complain on FIN recision.
		// That requires an extra state variable to avoid
		// generating slews of weird's when a TCP gets
		// seriously confused (this from experience).
		Weird("FIN_advanced_last_seq");

	// Previously, our state was CLOSED, since we sent a FIN.
	// If our peer was also closed, then don't change our state
	// now on a RST, since this connection has already seen a FIN
	// exchange.
	if ( flags.RST() && endpoint->peer->state != analyzer::tcp::TCP_ENDPOINT_CLOSED )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);

		if ( ! endpoint->did_close )
			// RST after FIN.
			do_close = true;

		if ( connection_reset )
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::ResetTimer,
			                   t + zeek::detail::tcp_reset_delay, true,
			                   zeek::detail::TIMER_TCP_RESET);
		}
	}

void TCPSessionAdapter::UpdateResetState(int len, analyzer::tcp::TCP_Flags flags)
	{
	if ( flags.SYN() )
		Weird("SYN_after_reset");

	if ( flags.FIN() )
		Weird("FIN_after_reset");

	if ( len > 0 && ! flags.RST() )
		Weird("data_after_reset");
	}

void TCPSessionAdapter::UpdateStateMachine(
	double t, analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
	uint32_t base_seq, uint32_t ack_seq,
	int len, int32_t delta_last, bool is_orig, analyzer::tcp::TCP_Flags flags,
	bool& do_close, bool& gen_event)
	{
	do_close = false;	// whether to report the connection as closed
	gen_event = false;	// if so, whether to generate an event

	switch ( endpoint->state ) {

	case analyzer::tcp::TCP_ENDPOINT_INACTIVE:
		UpdateInactiveState(t, endpoint, peer, base_seq, ack_seq,
					len, is_orig, flags,
					do_close, gen_event);
		break;

	case analyzer::tcp::TCP_ENDPOINT_SYN_SENT:
	case analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT:
		UpdateSYN_SentState(endpoint, peer, len, is_orig, flags, do_close,
		                    gen_event);
		break;

	case analyzer::tcp::TCP_ENDPOINT_ESTABLISHED:
	case analyzer::tcp::TCP_ENDPOINT_PARTIAL:
		UpdateEstablishedState(endpoint, peer, flags, do_close, gen_event);
		break;

	case analyzer::tcp::TCP_ENDPOINT_CLOSED:
		UpdateClosedState(t, endpoint, delta_last, flags, do_close);
		break;

	case analyzer::tcp::TCP_ENDPOINT_RESET:
		UpdateResetState(len, flags);
		break;
	}
	}

void TCPSessionAdapter::GeneratePacketEvent(
	uint64_t rel_seq, uint64_t rel_ack,
	const u_char* data, int len, int caplen,
	bool is_orig, analyzer::tcp::TCP_Flags flags)
	{
	EnqueueConnEvent(tcp_packet,
		ConnVal(),
		val_mgr->Bool(is_orig),
		make_intrusive<StringVal>(flags.AsString()),
		val_mgr->Count(rel_seq),
		val_mgr->Count(flags.ACK() ? rel_ack : 0),
		val_mgr->Count(len),
		// We need the min() here because Ethernet padding can lead to
		// caplen > len.
		make_intrusive<StringVal>(std::min(caplen, len), (const char*) data)
	);
	}

bool TCPSessionAdapter::DeliverData(double t, const u_char* data, int len, int caplen,
                                    const IP_Hdr* ip, const struct tcphdr* tp,
                                    analyzer::tcp::TCP_Endpoint* endpoint, uint64_t rel_data_seq,
                                    bool is_orig, analyzer::tcp::TCP_Flags flags)
	{
	return endpoint->DataSent(t, rel_data_seq, len, caplen, data, ip, tp);
	}

void TCPSessionAdapter::DeliverPacket(int len, const u_char* data, bool is_orig,
                                      uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	// Handle child_packet analyzers.  Note: This happens *after* the
	// packet has been processed and the TCP state updated.
	analyzer::analyzer_list::iterator next;

	for ( auto i = packet_children.begin(); i != packet_children.end(); /* nop */ )
		{
		auto child = *i;

		if ( child->IsFinished() || child->Removing() )
			{
			if ( child->Removing() )
				child->Done();

			DBG_LOG(DBG_ANALYZER, "%s deleted child %s",
			        fmt_analyzer(this).c_str(), fmt_analyzer(child).c_str());
			i = packet_children.erase(i);
			delete child;
			}
		else
			{
			child->NextPacket(len, data, is_orig, seq, ip, caplen);
			++i;
			}
		}

	if ( ! reassembling )
		ForwardPacket(len, data, is_orig, seq, ip, caplen);
	}

void TCPSessionAdapter::DeliverStream(int len, const u_char* data, bool orig)
	{
	Analyzer::DeliverStream(len, data, orig);
	}

void TCPSessionAdapter::Undelivered(uint64_t seq, int len, bool is_orig)
	{
	Analyzer::Undelivered(seq, len, orig);
	}

void TCPSessionAdapter::FlipRoles()
	{
	Analyzer::FlipRoles();

	session_mgr->tcp_stats.FlipState(orig->state, resp->state);
	analyzer::tcp::TCP_Endpoint* tmp_ep = resp;
	resp = orig;
	orig = tmp_ep;
	orig->is_orig = !orig->is_orig;
	resp->is_orig = !resp->is_orig;
	}

void TCPSessionAdapter::UpdateConnVal(RecordVal *conn_val)
	{
	auto orig_endp_val = conn_val->GetFieldAs<RecordVal>("orig");
	auto resp_endp_val = conn_val->GetFieldAs<RecordVal>("resp");

	orig_endp_val->Assign(0, orig->Size());
	orig_endp_val->Assign(1, orig->state);
	resp_endp_val->Assign(0, resp->Size());
	resp_endp_val->Assign(1, resp->state);

	// Call children's UpdateConnVal
	Analyzer::UpdateConnVal(conn_val);

	// Have to do packet_children ourselves.
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		(*i)->UpdateConnVal(conn_val);
	}

void TCPSessionAdapter::AttemptTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( (orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT ||
	      orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT) &&
	     resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
		{
		Event(connection_attempt);
		is_active = 0;

		// All done with this connection.
		session_mgr->Remove(Conn());
		}
	}

void TCPSessionAdapter::PartialCloseTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( orig->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
	     resp->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
	     (! orig->did_close || ! resp->did_close) )
		{
		if ( orig->state == analyzer::tcp::TCP_ENDPOINT_RESET ||
		     resp->state == analyzer::tcp::TCP_ENDPOINT_RESET )
			// Presumably the RST is what caused the partial
			// close.  Don't report it.
			return;

		Event(connection_partial_close);
		session_mgr->Remove(Conn());
		}
	}

void TCPSessionAdapter::ExpireTimer(double t)
	{
	if ( ! is_active )
		return;

	if ( Conn()->LastTime() + zeek::detail::tcp_connection_linger < t )
		{
		if ( orig->did_close || resp->did_close )
			{
			// No activity for tcp_connection_linger seconds, and
			// at least one side has closed.  See whether
			// connection has likely terminated.
			if ( (orig->did_close && resp->did_close) ||
			     (orig->state == analyzer::tcp::TCP_ENDPOINT_RESET ||
			      resp->state == analyzer::tcp::TCP_ENDPOINT_RESET) ||
			     (orig->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
			      resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE) )
				{
				// Either both closed, or one RST,
				// or half-closed.

				// The Timer has Ref()'d us and won't Unref()
				// us until we return, so it's safe to have
				// the session remove and Unref() us here.
				Event(connection_timeout);
				is_active = 0;
				session_mgr->Remove(Conn());
				return;
				}
			}

		if ( resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			{
			if ( orig->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
				{
				// Nothing ever happened on this connection.
				// This can occur when we see a trashed
				// packet - it's discarded by NextPacket
				// before setting up an attempt timer,
				// so we need to clean it up here.
				Event(connection_timeout);
				session_mgr->Remove(Conn());
				return;
				}
			}
		}

	// Connection still active, so reschedule timer.
	// ### if PQ_Element's were Obj's, could just Ref the timer
	// and adjust its value here, instead of creating a new timer.
	ADD_ANALYZER_TIMER(&TCPSessionAdapter::ExpireTimer, t + zeek::detail::tcp_session_timer,
	                   false, zeek::detail::TIMER_TCP_EXPIRE);
	}

void TCPSessionAdapter::ResetTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( ! BothClosed() )
		ConnectionReset();

	session_mgr->Remove(Conn());
	}

void TCPSessionAdapter::DeleteTimer(double /* t */)
	{
	session_mgr->Remove(Conn());
	}

void TCPSessionAdapter::ConnDeleteTimer(double t)
	{
	Conn()->DeleteTimer(t);
	}

void TCPSessionAdapter::SetContentsFile(unsigned int direction, FilePtr f)
	{
	if ( direction == CONTENTS_NONE )
		{
		orig->SetContentsFile(nullptr);
		resp->SetContentsFile(nullptr);
		}

	else
		{
		if ( direction == CONTENTS_ORIG || direction == CONTENTS_BOTH )
			orig->SetContentsFile(f);
		if ( direction == CONTENTS_RESP || direction == CONTENTS_BOTH )
			resp->SetContentsFile(f);
		}
	}

FilePtr TCPSessionAdapter::GetContentsFile(unsigned int direction) const
	{
	switch ( direction ) {
	case CONTENTS_NONE:
		return nullptr;

	case CONTENTS_ORIG:
		return orig->GetContentsFile();

	case CONTENTS_RESP:
		return resp->GetContentsFile();

	case CONTENTS_BOTH:
		if ( orig->GetContentsFile() != resp->GetContentsFile())
			// This is an "error".
			return nullptr;
		else
			return orig->GetContentsFile();

	default:
		break;
	}

	reporter->Error("bad direction %u in TCPSessionAdapter::GetContentsFile",
	                      direction);
	return nullptr;
	}

void TCPSessionAdapter::ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
                                         analyzer::tcp::TCP_Endpoint* peer,
                                         bool gen_event)
	{
	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		// Using this type of cast here is nasty (will crash if
		// we inadvertantly have a child analyzer that's not a
		// TCP_ApplicationAnalyzer), but we have to ...
		static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>
			(*i)->ConnectionClosed(endpoint, peer, gen_event);

	if ( DataPending(endpoint) )
		{
		// Don't close out the connection yet, there's still data to
		// deliver.
		close_deferred = 1;
		if ( ! deferred_gen_event )
			deferred_gen_event = gen_event;
		return;
		}

	close_deferred = 0;

	if ( endpoint->did_close )
		return;	// nothing new to report

	endpoint->did_close = true;

	int close_complete =
		endpoint->state == analyzer::tcp::TCP_ENDPOINT_RESET ||
					peer->did_close ||
					peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE;

	if ( DEBUG_tcp_connection_close )
		{
		DEBUG_MSG("%.6f close_complete=%d tcp_close_delay=%f\n",
		          run_state::network_time, close_complete, detail::tcp_close_delay);
		}

	if ( close_complete )
		{
		if ( endpoint->prev_state != analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
		     peer->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			{
			if ( deferred_gen_event )
				{
				gen_event = true;
				deferred_gen_event = 0;	// clear flag
				}

			// We have something interesting to report.
			if ( gen_event )
				{
				if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
					ConnectionFinished(true);
				else
					ConnectionFinished(false);
				}
			}

		CancelTimers();

		// Note, even if tcp_close_delay is zero, we can't
		// simply do:
		//
		//	session_mgr->Remove(this);
		//
		// here, because that would cause the object to be
		// deleted out from under us.
		if ( zeek::detail::tcp_close_delay != 0.0 )
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::ConnDeleteTimer,
			                   Conn()->LastTime() + zeek::detail::tcp_close_delay, false,
			                   zeek::detail::TIMER_CONN_DELETE);
		else
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::DeleteTimer, Conn()->LastTime(), false,
			                   zeek::detail::TIMER_TCP_DELETE);
		}

	else
		{ // We haven't yet seen a full close.
		if ( endpoint->prev_state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			{ // First time we've seen anything from this side.
			if ( connection_partial_close )
				ADD_ANALYZER_TIMER(&TCPSessionAdapter::PartialCloseTimer,
				                   Conn()->LastTime() + zeek::detail::tcp_partial_close_delay, false,
				                   zeek::detail::TIMER_TCP_PARTIAL_CLOSE );
			}

		else
			{
			// Create a timer to look for the other side closing,
			// too.
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::ExpireTimer,
			                   Conn()->LastTime() + zeek::detail::tcp_session_timer, false,
			                   zeek::detail::TIMER_TCP_EXPIRE);
			}
		}
	}

void TCPSessionAdapter::ConnectionFinished(bool half_finished)
	{
	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		// Again, nasty - see TCPSessionAdapter::ConnectionClosed.
		static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>
			(*i)->ConnectionFinished(half_finished);

	if ( half_finished )
		Event(connection_half_finished);
	else
		Event(connection_finished);

	is_active = 0;
	}

void TCPSessionAdapter::ConnectionReset()
	{
	Event(connection_reset);

	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(*i)->ConnectionReset();

	is_active = 0;
	}

bool TCPSessionAdapter::HadGap(bool is_orig) const
	{
	analyzer::tcp::TCP_Endpoint* endp = is_orig ? orig : resp;
	return endp && endp->HadGap();
	}

void TCPSessionAdapter::AddChildPacketAnalyzer(analyzer::Analyzer* a)
	{
	DBG_LOG(DBG_ANALYZER, "%s added packet child %s",
			this->GetAnalyzerName(), a->GetAnalyzerName());

	packet_children.push_back(a);
	a->SetParent(this);
	}

bool TCPSessionAdapter::DataPending(analyzer::tcp::TCP_Endpoint* closing_endp)
	{
	if ( Skipping() )
		return false;

	return closing_endp->DataPending();
	}

void TCPSessionAdapter::EndpointEOF(analyzer::tcp::TCP_Reassembler* endp)
	{
	if ( connection_EOF )
		EnqueueConnEvent(connection_EOF,
			ConnVal(),
			val_mgr->Bool(endp->IsOrig())
		);

	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(*i)->EndpointEOF(endp->IsOrig());

	if ( close_deferred )
		{
		if ( DataPending(endp->Endpoint()) )
			{
			if ( BothClosed() )
				Weird("pending_data_when_closed");

			// Defer further, until the other endpoint
			// EOF's, too.
			}

		ConnectionClosed(endp->Endpoint(), endp->Endpoint()->peer,
					deferred_gen_event);
		close_deferred = 0;
		}
	}

void TCPSessionAdapter::PacketWithRST()
	{
	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		static_cast<analyzer::tcp::TCP_ApplicationAnalyzer *>(*i)->PacketWithRST();
	}

void TCPSessionAdapter::CheckPIA_FirstPacket(bool is_orig, const IP_Hdr* ip)
	{
	if ( is_orig && ! (first_packet_seen & ORIG) )
		{
		if ( auto* pia = static_cast<analyzer::pia::PIA_TCP*>(Conn()->GetPrimaryPIA()) )
			pia->FirstPacket(is_orig, ip);
		first_packet_seen |= ORIG;
		}

	if ( ! is_orig && ! (first_packet_seen & RESP) )
		{
		if ( auto* pia = static_cast<analyzer::pia::PIA_TCP*>(Conn()->GetPrimaryPIA()) )
			pia->FirstPacket(is_orig, ip);
		first_packet_seen |= RESP;
		}
	}

bool TCPSessionAdapter::IsReuse(double t, const u_char* pkt)
	{
	const struct tcphdr* tp = (const struct tcphdr*) pkt;

	if ( unsigned(tp->th_off) < sizeof(struct tcphdr) / 4 )
		// Bogus header, don't interpret further.
		return false;

	analyzer::tcp::TCP_Endpoint* conn_orig = orig;

	// Reuse only occurs on initial SYN's, except for half connections
	// it can occur on SYN-acks.
	if ( ! (tp->th_flags & TH_SYN) )
		return false;

	if ( (tp->th_flags & TH_ACK) )
		{
		if ( orig->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			// Not a half connection.
			return false;

		conn_orig = resp;
		}

	if ( ! IsClosed() )
		{
		uint32_t base_seq = ntohl(tp->th_seq);
		if ( base_seq == conn_orig->StartSeq() )
			return false;

		if ( (tp->th_flags & TH_ACK) == 0 &&
		     conn_orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT &&
		     resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
		     base_seq == resp->StartSeq() )
			{
			// This is an initial SYN with the right sequence
			// number, and the state is consistent with the
			// SYN & the SYN-ACK being flipped (e.g., due to
			// reading from two interfaces w/ interrupt
			// coalescence).  Don't treat this as a reuse.
			// NextPacket() will flip set the connection
			// state correctly
			return false;
			}

		if ( conn_orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
			Weird("SYN_seq_jump");
		else
			Weird("active_connection_reuse");
		}

	else if ( (orig->IsActive() || resp->IsActive()) &&
		  orig->state != analyzer::tcp::TCP_ENDPOINT_RESET &&
		  resp->state != analyzer::tcp::TCP_ENDPOINT_RESET )
		Weird("active_connection_reuse");

	else if ( t - Conn()->LastTime() < zeek::detail::tcp_connection_linger &&
		  orig->state != analyzer::tcp::TCP_ENDPOINT_RESET &&
		  resp->state != analyzer::tcp::TCP_ENDPOINT_RESET )
		Weird("premature_connection_reuse");

	return true;
	}

void TCPSessionAdapter::AddExtraAnalyzers(Connection* conn)
	{
	static analyzer::Tag analyzer_connsize = analyzer_mgr->GetComponentTag("CONNSIZE");
	static analyzer::Tag analyzer_stepping = analyzer_mgr->GetComponentTag("STEPPINGSTONE");
	static analyzer::Tag analyzer_tcpstats = analyzer_mgr->GetComponentTag("TCPSTATS");

	// We have to decide whether to reassamble the stream.
	// We turn it on right away if we already have an app-layer
	// analyzer, reassemble_first_packets is true, or the user
	// asks us to do so.  In all other cases, reassembly may
	// be turned on later by the TCP PIA.

	bool reass = ( ! GetChildren().empty() ) ||
		zeek::detail::dpd_reassemble_first_packets ||
		zeek::detail::tcp_content_deliver_all_orig ||
		zeek::detail::tcp_content_deliver_all_resp;

	if ( tcp_contents && ! reass )
		{
		static auto tcp_content_delivery_ports_orig = id::find_val<TableVal>("tcp_content_delivery_ports_orig");
		static auto tcp_content_delivery_ports_resp = id::find_val<TableVal>("tcp_content_delivery_ports_resp");
		const auto& dport = val_mgr->Port(ntohs(conn->RespPort()), TRANSPORT_TCP);

		if ( ! reass )
			reass = (bool)tcp_content_delivery_ports_orig->FindOrDefault(dport);

		if ( ! reass )
			reass = (bool)tcp_content_delivery_ports_resp->FindOrDefault(dport);
		}

	if ( reass )
		EnableReassembly();

	if ( analyzer_mgr->IsEnabled(analyzer_stepping) )
		{
		// Add a SteppingStone analyzer if requested.  The port
		// should really not be hardcoded here, but as it can
		// handle non-reassembled data, it doesn't really fit into
		// our general framing ...  Better would be to turn it
		// on *after* we discover we have interactive traffic.
		uint16_t resp_port = ntohs(conn->RespPort());
		if ( resp_port == 22 || resp_port == 23 || resp_port == 513 )
			{
			static auto stp_skip_src = id::find_val<TableVal>("stp_skip_src");
			auto src = make_intrusive<AddrVal>(conn->OrigAddr());

			if ( ! stp_skip_src->FindOrDefault(src) )
				AddChildAnalyzer(new analyzer::stepping_stone::SteppingStone_Analyzer(conn), false);
			}
		}

	if ( analyzer_mgr->IsEnabled(analyzer_tcpstats) )
		// Add TCPStats analyzer. This needs to see packets so
		// we cannot add it as a normal child.
		AddChildPacketAnalyzer(new analyzer::tcp::TCPStats_Analyzer(conn));

	if ( analyzer_mgr->IsEnabled(analyzer_connsize) )
		// Add ConnSize analyzer. Needs to see packets, not stream.
		AddChildPacketAnalyzer(new analyzer::conn_size::ConnSize_Analyzer(conn));
	}
