// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "zeek/Conn.h"

#include <ctype.h>
#include <binpac.h>

#include "zeek/Desc.h"
#include "zeek/RunState.h"
#include "zeek/NetVar.h"
#include "zeek/Event.h"
#include "zeek/Sessions.h"
#include "zeek/Reporter.h"
#include "zeek/Timer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/iosource/IOSource.h"

namespace zeek {
namespace detail {

void ConnectionTimer::Init(Connection* arg_conn, timer_func arg_timer,
                           bool arg_do_expire)
	{
	conn = arg_conn;
	timer = arg_timer;
	do_expire = arg_do_expire;
	Ref(conn);
	}

ConnectionTimer::~ConnectionTimer()
	{
	if ( conn->RefCnt() < 1 )
		reporter->InternalError("reference count inconsistency in ~ConnectionTimer");

	conn->RemoveTimer(this);
	Unref(conn);
	}

void ConnectionTimer::Dispatch(double t, bool is_expire)
	{
	if ( is_expire && ! do_expire )
		return;

	// Remove ourselves from the connection's set of timers so
	// it doesn't try to cancel us.
	conn->RemoveTimer(this);

	(conn->*timer)(t);

	if ( conn->RefCnt() < 1 )
		reporter->InternalError("reference count inconsistency in ConnectionTimer::Dispatch");
	}

} // namespace detail

uint64_t Connection::total_connections = 0;
uint64_t Connection::current_connections = 0;

Connection::Connection(NetSessions* s, const detail::ConnIDKey& k, double t,
                       const ConnID* id, uint32_t flow, const Packet* pkt)
	{
	sessions = s;
	key = k;
	key_valid = true;
	start_time = last_time = t;

	orig_addr = id->src_addr;
	resp_addr = id->dst_addr;
	orig_port = id->src_port;
	resp_port = id->dst_port;
	proto = TRANSPORT_UNKNOWN;
	orig_flow_label = flow;
	resp_flow_label = 0;
	saw_first_orig_packet = 1;
	saw_first_resp_packet = 0;

	if ( pkt->l2_src )
		memcpy(orig_l2_addr, pkt->l2_src, sizeof(orig_l2_addr));
	else
		memset(orig_l2_addr, 0, sizeof(orig_l2_addr));

	if ( pkt->l2_dst )
		memcpy(resp_l2_addr, pkt->l2_dst, sizeof(resp_l2_addr));
	else
		memset(resp_l2_addr, 0, sizeof(resp_l2_addr));

	vlan = pkt->vlan;
	inner_vlan = pkt->inner_vlan;

	is_active = 1;
	skip = 0;
	weird = 0;

	suppress_event = 0;

	record_contents = record_packets = 1;
	record_current_packet = record_current_content = 0;

	timers_canceled = 0;
	inactivity_timeout = 0;
	installed_status_timer = 0;

	finished = 0;

	hist_seen = 0;
	history = "";

	root_analyzer = nullptr;
	primary_PIA = nullptr;

	++current_connections;
	++total_connections;

	encapsulation = pkt->encap;
	}

Connection::~Connection()
	{
	if ( ! finished )
		reporter->InternalError("Done() not called before destruction of Connection");

	CancelTimers();

	if ( conn_val )
		conn_val->SetOrigin(nullptr);

	delete root_analyzer;

	--current_connections;
	}

void Connection::CheckEncapsulation(const std::shared_ptr<EncapsulationStack>& arg_encap)
	{
	if ( encapsulation && arg_encap )
		{
		if ( *encapsulation != *arg_encap )
			{
			if ( tunnel_changed )
				EnqueueEvent(tunnel_changed, nullptr, ConnVal(),
				             arg_encap->ToVal());

			encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
			}
		}

	else if ( encapsulation )
		{
		if ( tunnel_changed )
			{
			EncapsulationStack empty;
			EnqueueEvent(tunnel_changed, nullptr, ConnVal(), empty.ToVal());
			}

		encapsulation = nullptr;
		}

	else if ( arg_encap )
		{
		if ( tunnel_changed )
			EnqueueEvent(tunnel_changed, nullptr, ConnVal(), arg_encap->ToVal());

		encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
		}
	}

void Connection::Done()
	{
	finished = 1;

	if ( root_analyzer && ! root_analyzer->IsFinished() )
		root_analyzer->Done();
	}

void Connection::NextPacket(double t, bool is_orig,
                            const IP_Hdr* ip, int len, int caplen,
                            const u_char*& data,
                            int& record_packet, int& record_content,
                            // arguments for reproducing packets
                            const Packet *pkt)
	{
	run_state::current_timestamp = t;
	run_state::current_pkt = pkt;

	if ( Skipping() )
		return;

	if ( root_analyzer )
		{
		record_current_packet = record_packet;
		record_current_content = record_content;
		root_analyzer->NextPacket(len, data, is_orig, -1, ip, caplen);
		record_packet = record_current_packet;
		record_content = record_current_content;
		}
	else
		last_time = t;

	run_state::current_timestamp = 0;
	run_state::current_pkt = nullptr;
	}

void Connection::SetLifetime(double lifetime)
	{
	ADD_TIMER(&Connection::DeleteTimer, run_state::network_time + lifetime, 0,
	          detail::TIMER_CONN_DELETE);
	}

bool Connection::IsReuse(double t, const u_char* pkt)
	{
	return root_analyzer && root_analyzer->IsReuse(t, pkt);
	}

bool Connection::ScaledHistoryEntry(char code, uint32_t& counter,
                                    uint32_t& scaling_threshold,
                                    uint32_t scaling_base)
	{
	if ( ++counter == scaling_threshold )
		{
		AddHistory(code);

		auto new_threshold = scaling_threshold * scaling_base;

		if ( new_threshold <= scaling_threshold )
			// This can happen due to wrap-around.  In that
			// case, reset the counter but leave the threshold
			// unchanged.
			counter = 0;

		else
			scaling_threshold = new_threshold;

		return true;
		}

	return false;
	}

void Connection::HistoryThresholdEvent(EventHandlerPtr e, bool is_orig,
                                       uint32_t threshold)
	{
	if ( ! e )
		return;

	if ( threshold == 1 )
		// This will be far and away the most common case,
		// and at this stage it's not a *multiple* instance.
		return;

	EnqueueEvent(e, nullptr,
		ConnVal(),
		val_mgr->Bool(is_orig),
		val_mgr->Count(threshold)
	);
	}

void Connection::DeleteTimer(double /* t */)
	{
	if ( is_active )
		Event(connection_timeout, nullptr);

	sessions->Remove(this);
	}

void Connection::InactivityTimer(double t)
	{
	if ( last_time + inactivity_timeout <= t )
		{
		Event(connection_timeout, nullptr);
		sessions->Remove(this);
		++detail::killed_by_inactivity;
		}
	else
		ADD_TIMER(&Connection::InactivityTimer,
		          last_time + inactivity_timeout, 0,
		          detail::TIMER_CONN_INACTIVITY);
	}

void Connection::RemoveConnectionTimer(double t)
	{
	RemovalEvent();
	sessions->Remove(this);
	}

void Connection::SetInactivityTimeout(double timeout)
	{
	if ( timeout == inactivity_timeout )
		return;

	// First cancel and remove any existing inactivity timer.
	for ( const auto& timer : timers )
		if ( timer->Type() == detail::TIMER_CONN_INACTIVITY )
			{
			detail::timer_mgr->Cancel(timer);
			break;
			}

	if ( timeout )
		ADD_TIMER(&Connection::InactivityTimer,
		          last_time + timeout, 0, detail::TIMER_CONN_INACTIVITY);

	inactivity_timeout = timeout;
	}

void Connection::EnableStatusUpdateTimer()
	{
	if ( installed_status_timer )
		return;

	if ( connection_status_update && zeek::detail::connection_status_update_interval )
		{
		ADD_TIMER(&Connection::StatusUpdateTimer,
		          run_state::network_time + detail::connection_status_update_interval, 0,
		          detail::TIMER_CONN_STATUS_UPDATE);
		installed_status_timer = 1;
		}
	}

void Connection::StatusUpdateTimer(double t)
	{
	EnqueueEvent(connection_status_update, nullptr, ConnVal());
	ADD_TIMER(&Connection::StatusUpdateTimer,
	          run_state::network_time + detail::connection_status_update_interval, 0,
	          detail::TIMER_CONN_STATUS_UPDATE);
	}

const RecordValPtr& Connection::ConnVal()
	{
	if ( ! conn_val )
		{
		conn_val = make_intrusive<RecordVal>(id::connection);

		TransportProto prot_type = ConnTransport();

		auto id_val = make_intrusive<RecordVal>(id::conn_id);
		id_val->Assign(0, make_intrusive<AddrVal>(orig_addr));
		id_val->Assign(1, val_mgr->Port(ntohs(orig_port), prot_type));
		id_val->Assign(2, make_intrusive<AddrVal>(resp_addr));
		id_val->Assign(3, val_mgr->Port(ntohs(resp_port), prot_type));

		auto orig_endp = make_intrusive<RecordVal>(id::endpoint);
		orig_endp->Assign(0, val_mgr->Count(0));
		orig_endp->Assign(1, val_mgr->Count(0));
		orig_endp->Assign(4, val_mgr->Count(orig_flow_label));

		const int l2_len = sizeof(orig_l2_addr);
		char null[l2_len]{};

		if ( memcmp(&orig_l2_addr, &null, l2_len) != 0 )
			orig_endp->Assign(5, make_intrusive<StringVal>(fmt_mac(orig_l2_addr, l2_len)));

		auto resp_endp = make_intrusive<RecordVal>(id::endpoint);
		resp_endp->Assign(0, val_mgr->Count(0));
		resp_endp->Assign(1, val_mgr->Count(0));
		resp_endp->Assign(4, val_mgr->Count(resp_flow_label));

		if ( memcmp(&resp_l2_addr, &null, l2_len) != 0 )
			resp_endp->Assign(5, make_intrusive<StringVal>(fmt_mac(resp_l2_addr, l2_len)));

		conn_val->Assign(0, std::move(id_val));
		conn_val->Assign(1, std::move(orig_endp));
		conn_val->Assign(2, std::move(resp_endp));
		// 3 and 4 are set below.
		conn_val->Assign(5, make_intrusive<TableVal>(id::string_set));	// service
		conn_val->Assign(6, val_mgr->EmptyString());	// history

		if ( ! uid )
			uid.Set(zeek::detail::bits_per_uid);

		conn_val->Assign(7, make_intrusive<StringVal>(uid.Base62("C").c_str()));

		if ( encapsulation && encapsulation->Depth() > 0 )
			conn_val->Assign(8, encapsulation->ToVal());

		if ( vlan != 0 )
			conn_val->Assign(9, val_mgr->Int(vlan));

		if ( inner_vlan != 0 )
			conn_val->Assign(10, val_mgr->Int(inner_vlan));

		}

	if ( root_analyzer )
		root_analyzer->UpdateConnVal(conn_val.get());

	conn_val->Assign(3, make_intrusive<TimeVal>(start_time));	// ###
	conn_val->Assign(4, make_intrusive<IntervalVal>(last_time - start_time));
	conn_val->Assign(6, make_intrusive<StringVal>(history.c_str()));

	conn_val->SetOrigin(this);

	return conn_val;
	}

analyzer::Analyzer* Connection::FindAnalyzer(analyzer::ID id)
	{
	return root_analyzer ? root_analyzer->FindChild(id) : nullptr;
	}

analyzer::Analyzer* Connection::FindAnalyzer(const analyzer::Tag& tag)
	{
	return root_analyzer ? root_analyzer->FindChild(tag) : nullptr;
	}

analyzer::Analyzer* Connection::FindAnalyzer(const char* name)
	{
	return root_analyzer->FindChild(name);
	}

void Connection::AppendAddl(const char* str)
	{
	const auto& cv = ConnVal();

	const char* old = cv->GetFieldAs<StringVal>(6)->CheckString();
	const char* format = *old ? "%s %s" : "%s%s";

	cv->Assign(6, make_intrusive<StringVal>(util::fmt(format, old, str)));
	}

// Returns true if the character at s separates a version number.
static inline bool is_version_sep(const char* s, const char* end)
	{
	return
		// foo-1.2.3
			(s < end - 1 && ispunct(s[0]) && isdigit(s[1])) ||
		// foo-v1.2.3
			(s < end - 2 && ispunct(s[0]) &&
			 tolower(s[1]) == 'v' && isdigit(s[2])) ||
		// foo 1.2.3
			isspace(s[0]);
	}

void Connection::Match(detail::Rule::PatternType type, const u_char* data, int len,
                       bool is_orig, bool bol, bool eol, bool clear_state)
	{
	if ( primary_PIA )
		primary_PIA->Match(type, data, len, is_orig, bol, eol, clear_state);
	}

void Connection::RemovalEvent()
	{
	if ( connection_state_remove )
		EnqueueEvent(connection_state_remove, nullptr, ConnVal());
	}

void Connection::Event(EventHandlerPtr f, analyzer::Analyzer* analyzer, const char* name)
	{
	if ( ! f )
		return;

	if ( name )
		EnqueueEvent(f, analyzer, make_intrusive<StringVal>(name), ConnVal());
	else
		EnqueueEvent(f, analyzer, ConnVal());
	}

void Connection::EnqueueEvent(EventHandlerPtr f, analyzer::Analyzer* a,
                              Args args)
	{
	// "this" is passed as a cookie for the event
	event_mgr.Enqueue(f, std::move(args), util::detail::SOURCE_LOCAL, a ? a->GetID() : 0, this);
	}

void Connection::Weird(const char* name, const char* addl, const char* source)
	{
	weird = 1;
	reporter->Weird(this, name, addl ? addl : "", source ? source : "");
	}

void Connection::AddTimer(timer_func timer, double t, bool do_expire,
                          detail::TimerType type)
	{
	if ( timers_canceled )
		return;

	// If the key is cleared, the connection isn't stored in the connection
	// table anymore and will soon be deleted. We're not installing new
	// timers anymore then.
	if ( ! key_valid )
		return;

	detail::Timer* conn_timer = new detail::ConnectionTimer(this, timer, t, do_expire, type);
	detail::timer_mgr->Add(conn_timer);
	timers.push_back(conn_timer);
	}

void Connection::RemoveTimer(detail::Timer* t)
	{
	timers.remove(t);
	}

void Connection::CancelTimers()
	{
	// We are going to cancel our timers which, in turn, may cause them to
	// call RemoveTimer(), which would then modify the list we're just
	// traversing. Thus, we first make a copy of the list which we then
	// iterate through.
	TimerPList tmp(timers.length());
	std::copy(timers.begin(), timers.end(), std::back_inserter(tmp));

	for ( const auto& timer : tmp )
		detail::timer_mgr->Cancel(timer);

	timers_canceled = 1;
	timers.clear();
	}

void Connection::FlipRoles()
	{
	IPAddr tmp_addr = resp_addr;
	resp_addr = orig_addr;
	orig_addr = tmp_addr;

	uint32_t tmp_port = resp_port;
	resp_port = orig_port;
	orig_port = tmp_port;

	const int l2_len = sizeof(orig_l2_addr);
	u_char tmp_l2_addr[l2_len];
	memcpy(tmp_l2_addr, resp_l2_addr, l2_len);
	memcpy(resp_l2_addr, orig_l2_addr, l2_len);
	memcpy(orig_l2_addr, tmp_l2_addr, l2_len);

	bool tmp_bool = saw_first_resp_packet;
	saw_first_resp_packet = saw_first_orig_packet;
	saw_first_orig_packet = tmp_bool;

	uint32_t tmp_flow = resp_flow_label;
	resp_flow_label = orig_flow_label;
	orig_flow_label = tmp_flow;

	conn_val = nullptr;

	if ( root_analyzer )
		root_analyzer->FlipRoles();

	analyzer_mgr->ApplyScheduledAnalyzers(this);

	AddHistory('^');
	}

unsigned int Connection::MemoryAllocation() const
	{
	return padded_sizeof(*this)
		+ (timers.MemoryAllocation() - padded_sizeof(timers))
		+ (conn_val ? conn_val->MemoryAllocation() : 0)
		+ (root_analyzer ? root_analyzer->MemoryAllocation(): 0)
		// primary_PIA is already contained in the analyzer tree.
		;
	}

unsigned int Connection::MemoryAllocationConnVal() const
	{
	return conn_val ? conn_val->MemoryAllocation() : 0;
	}

void Connection::Describe(ODesc* d) const
	{
	d->Add(start_time);
	d->Add("(");
	d->Add(last_time);
	d->AddSP(")");

	switch ( proto ) {
		case TRANSPORT_TCP:
			d->Add("TCP");
			break;

		case TRANSPORT_UDP:
			d->Add("UDP");
			break;

		case TRANSPORT_ICMP:
			d->Add("ICMP");
			break;

		case TRANSPORT_UNKNOWN:
			d->Add("unknown");
			reporter->InternalWarning(
				"unknown transport in Connction::Describe()");

			break;

		default:
			reporter->InternalError(
				"unhandled transport type in Connection::Describe");
		}

	d->SP();
	d->Add(orig_addr);
	d->Add(":");
	d->Add(ntohs(orig_port));

	d->SP();
	d->AddSP("->");

	d->Add(resp_addr);
	d->Add(":");
	d->Add(ntohs(resp_port));

	d->NL();
	}

void Connection::IDString(ODesc* d) const
	{
	d->Add(orig_addr);
	d->AddRaw(":", 1);
	d->Add(ntohs(orig_port));
	d->AddRaw(" > ", 3);
	d->Add(resp_addr);
	d->AddRaw(":", 1);
	d->Add(ntohs(resp_port));
	}

void Connection::SetRootAnalyzer(analyzer::TransportLayerAnalyzer* analyzer,
                                 analyzer::pia::PIA* pia)
	{
	root_analyzer = analyzer;
	primary_PIA = pia;
	}

void Connection::CheckFlowLabel(bool is_orig, uint32_t flow_label)
	{
	uint32_t& my_flow_label = is_orig ? orig_flow_label : resp_flow_label;

	if ( my_flow_label != flow_label )
		{
		if ( conn_val )
			{
			RecordVal* endp = conn_val->GetField(is_orig ? 1 : 2)->AsRecordVal();
			endp->Assign(4, val_mgr->Count(flow_label));
			}

		if ( connection_flow_label_changed &&
		     (is_orig ? saw_first_orig_packet : saw_first_resp_packet) )
			{
			EnqueueEvent(connection_flow_label_changed, nullptr,
				ConnVal(),
				val_mgr->Bool(is_orig),
				val_mgr->Count(my_flow_label),
				val_mgr->Count(flow_label)
			);
			}

		my_flow_label = flow_label;
		}

	if ( is_orig )
		saw_first_orig_packet = 1;
	else
		saw_first_resp_packet = 1;
	}

bool Connection::PermitWeird(const char* name, uint64_t threshold, uint64_t rate,
                             double duration)
	{
	return detail::PermitWeird(weird_state, name, threshold, rate, duration);
	}

} // namespace zeek
