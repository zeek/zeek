// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Conn.h"

#include <ctype.h>

#include "Desc.h"
#include "Net.h"
#include "NetVar.h"
#include "Event.h"
#include "Sessions.h"
#include "Reporter.h"
#include "Timer.h"
#include "iosource/IOSource.h"
#include "analyzer/protocol/pia/PIA.h"
#include "binpac.h"
#include "TunnelEncapsulation.h"
#include "analyzer/Analyzer.h"
#include "analyzer/Manager.h"
#include "iosource/IOSource.h"

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

void ConnectionTimer::Dispatch(double t, int is_expire)
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

uint64_t Connection::total_connections = 0;
uint64_t Connection::current_connections = 0;

Connection::Connection(NetSessions* s, const ConnIDKey& k, double t, const ConnID* id,
                       uint32_t flow, const Packet* pkt,
                       const EncapsulationStack* arg_encap)
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
	is_successful = false;

	if ( pkt->l2_src )
		memcpy(orig_l2_addr, pkt->l2_src, sizeof(orig_l2_addr));
	else
		bzero(orig_l2_addr, sizeof(orig_l2_addr));

	if ( pkt->l2_dst )
		memcpy(resp_l2_addr, pkt->l2_dst, sizeof(resp_l2_addr));
	else
		bzero(resp_l2_addr, sizeof(resp_l2_addr));

	vlan = pkt->vlan;
	inner_vlan = pkt->inner_vlan;

	conn_val = nullptr;
	login_conn = nullptr;

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

	if ( arg_encap )
		encapsulation = new EncapsulationStack(*arg_encap);
	else
		encapsulation = 0;
	}

Connection::~Connection()
	{
	if ( ! finished )
		reporter->InternalError("Done() not called before destruction of Connection");

	CancelTimers();

	if ( conn_val )
		{
		conn_val->SetOrigin(0);
		Unref(conn_val);
		}

	delete root_analyzer;
	delete encapsulation;

	--current_connections;
	}

void Connection::CheckEncapsulation(const EncapsulationStack* arg_encap)
	{
	if ( encapsulation && arg_encap )
		{
		if ( *encapsulation != *arg_encap )
			{
			Event(tunnel_changed, 0, arg_encap->GetVectorVal());
			delete encapsulation;
			encapsulation = new EncapsulationStack(*arg_encap);
			}
		}

	else if ( encapsulation )
		{
		EncapsulationStack empty;
		Event(tunnel_changed, 0, empty.GetVectorVal());
		delete encapsulation;
		encapsulation = nullptr;
		}

	else if ( arg_encap )
		{
		Event(tunnel_changed, 0, arg_encap->GetVectorVal());
		encapsulation = new EncapsulationStack(*arg_encap);
		}
	}

void Connection::Done()
	{
	finished = 1;

	if ( root_analyzer && ! root_analyzer->IsFinished() )
		root_analyzer->Done();
	}

void Connection::NextPacket(double t, int is_orig,
			const IP_Hdr* ip, int len, int caplen,
			const u_char*& data,
			int& record_packet, int& record_content,
			// arguments for reproducing packets
			const Packet *pkt)
	{
	current_timestamp = t;
	current_pkt = pkt;

	if ( Skipping() )
		return;

	if ( root_analyzer )
		{
		auto was_successful = is_successful;
		record_current_packet = record_packet;
		record_current_content = record_content;
		root_analyzer->NextPacket(len, data, is_orig, -1, ip, caplen);
		record_packet = record_current_packet;
		record_content = record_current_content;

		if ( ConnTransport() != TRANSPORT_TCP )
			is_successful = true;

		if ( ! was_successful && is_successful && connection_successful )
			ConnectionEventFast(connection_successful, nullptr, {BuildConnVal()});
		}
	else
		last_time = t;

	current_timestamp = 0;
	current_pkt = nullptr;
	}

void Connection::SetLifetime(double lifetime)
	{
	ADD_TIMER(&Connection::DeleteTimer, network_time + lifetime, 0,
			TIMER_CONN_DELETE);
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

	ConnectionEventFast(e, 0, {
		BuildConnVal(),
		val_mgr->GetBool(is_orig),
		val_mgr->GetCount(threshold)
	});
	}

void Connection::DeleteTimer(double /* t */)
	{
	if ( is_active )
		Event(connection_timeout, 0);

	sessions->Remove(this);
	}

void Connection::InactivityTimer(double t)
	{
	// If the inactivity_timeout is zero, there has been an active
	// timeout once, but it's disabled now. We do nothing then.
	if ( inactivity_timeout )
		{
		if ( last_time + inactivity_timeout <= t )
			{
			Event(connection_timeout, 0);
			sessions->Remove(this);
			++killed_by_inactivity;
			}
		else
			ADD_TIMER(&Connection::InactivityTimer,
					last_time + inactivity_timeout, 0,
					TIMER_CONN_INACTIVITY);
		}
	}

void Connection::RemoveConnectionTimer(double t)
	{
	RemovalEvent();
	sessions->Remove(this);
	}

void Connection::SetInactivityTimeout(double timeout)
	{
	// We add a new inactivity timer even if there already is one.  When
	// it fires, we always use the current value to check for inactivity.
	if ( timeout )
		ADD_TIMER(&Connection::InactivityTimer,
				last_time + timeout, 0, TIMER_CONN_INACTIVITY);

	inactivity_timeout = timeout;
	}

void Connection::EnableStatusUpdateTimer()
	{
	if ( connection_status_update && connection_status_update_interval )
		{
		ADD_TIMER(&Connection::StatusUpdateTimer,
			network_time + connection_status_update_interval, 0,
			TIMER_CONN_STATUS_UPDATE);
		installed_status_timer = 1;
		}
	}

void Connection::StatusUpdateTimer(double t)
	{
	ConnectionEventFast(connection_status_update, 0, { BuildConnVal() });
	ADD_TIMER(&Connection::StatusUpdateTimer,
			network_time + connection_status_update_interval, 0,
			TIMER_CONN_STATUS_UPDATE);
	}

RecordVal* Connection::BuildConnVal()
	{
	if ( ! conn_val )
		{
		conn_val = new RecordVal(connection_type);

		TransportProto prot_type = ConnTransport();

		RecordVal* id_val = new RecordVal(conn_id);
		id_val->Assign(0, new AddrVal(orig_addr));
		id_val->Assign(1, val_mgr->GetPort(ntohs(orig_port), prot_type));
		id_val->Assign(2, new AddrVal(resp_addr));
		id_val->Assign(3, val_mgr->GetPort(ntohs(resp_port), prot_type));

		RecordVal* orig_endp = new RecordVal(endpoint);
		orig_endp->Assign(0, val_mgr->GetCount(0));
		orig_endp->Assign(1, val_mgr->GetCount(0));
		orig_endp->Assign(4, val_mgr->GetCount(orig_flow_label));

		const int l2_len = sizeof(orig_l2_addr);
		char null[l2_len]{};

		if ( memcmp(&orig_l2_addr, &null, l2_len) != 0 )
			orig_endp->Assign(5, new StringVal(fmt_mac(orig_l2_addr, l2_len)));

		RecordVal* resp_endp = new RecordVal(endpoint);
		resp_endp->Assign(0, val_mgr->GetCount(0));
		resp_endp->Assign(1, val_mgr->GetCount(0));
		resp_endp->Assign(4, val_mgr->GetCount(resp_flow_label));

		if ( memcmp(&resp_l2_addr, &null, l2_len) != 0 )
			resp_endp->Assign(5, new StringVal(fmt_mac(resp_l2_addr, l2_len)));

		conn_val->Assign(0, id_val);
		conn_val->Assign(1, orig_endp);
		conn_val->Assign(2, resp_endp);
		// 3 and 4 are set below.
		conn_val->Assign(5, new TableVal(string_set));	// service
		conn_val->Assign(6, val_mgr->GetEmptyString());	// history

		if ( ! uid )
			uid.Set(bits_per_uid);

		conn_val->Assign(7, new StringVal(uid.Base62("C").c_str()));

		if ( encapsulation && encapsulation->Depth() > 0 )
			conn_val->Assign(8, encapsulation->GetVectorVal());

		if ( vlan != 0 )
			conn_val->Assign(9, val_mgr->GetInt(vlan));

		if ( inner_vlan != 0 )
			conn_val->Assign(10, val_mgr->GetInt(inner_vlan));

		}

	if ( root_analyzer )
		root_analyzer->UpdateConnVal(conn_val);

	conn_val->Assign(3, new Val(start_time, TYPE_TIME));	// ###
	conn_val->Assign(4, new Val(last_time - start_time, TYPE_INTERVAL));
	conn_val->Assign(6, new StringVal(history.c_str()));
	conn_val->Assign(11, val_mgr->GetBool(is_successful));

	conn_val->SetOrigin(this);

	Ref(conn_val);

	return conn_val;
	}

analyzer::Analyzer* Connection::FindAnalyzer(analyzer::ID id)
	{
	return root_analyzer ? root_analyzer->FindChild(id) : 0;
	}

analyzer::Analyzer* Connection::FindAnalyzer(const analyzer::Tag& tag)
	{
	return root_analyzer ? root_analyzer->FindChild(tag) : 0;
	}

analyzer::Analyzer* Connection::FindAnalyzer(const char* name)
	{
	return root_analyzer->FindChild(name);
	}

void Connection::AppendAddl(const char* str)
	{
	Unref(BuildConnVal());

	const char* old = conn_val->Lookup(6)->AsString()->CheckString();
	const char* format = *old ? "%s %s" : "%s%s";

	conn_val->Assign(6, new StringVal(fmt(format, old, str)));
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

void Connection::Match(Rule::PatternType type, const u_char* data, int len, bool is_orig, bool bol, bool eol, bool clear_state)
	{
	if ( primary_PIA )
		primary_PIA->Match(type, data, len, is_orig, bol, eol, clear_state);
	}

void Connection::RemovalEvent()
	{
	auto cv = BuildConnVal();

	if ( connection_state_remove )
		ConnectionEventFast(connection_state_remove, nullptr, {cv->Ref()});

	if ( is_successful && successful_connection_remove )
		ConnectionEventFast(successful_connection_remove, nullptr, {cv->Ref()});

	Unref(cv);
	}

void Connection::Event(EventHandlerPtr f, analyzer::Analyzer* analyzer, const char* name)
	{
	if ( ! f )
		return;

	if ( name )
		ConnectionEventFast(f, analyzer, {new StringVal(name), BuildConnVal()});
	else
		ConnectionEventFast(f, analyzer, {BuildConnVal()});

	}

void Connection::Event(EventHandlerPtr f, analyzer::Analyzer* analyzer, Val* v1, Val* v2)
	{
	if ( ! f )
		{
		Unref(v1);
		Unref(v2);
		return;
		}

	if ( v2 )
		ConnectionEventFast(f, analyzer, {BuildConnVal(), v1, v2});
	else
		ConnectionEventFast(f, analyzer, {BuildConnVal(), v1});
	}

void Connection::ConnectionEvent(EventHandlerPtr f, analyzer::Analyzer* a, val_list vl)
	{
	if ( ! f )
		{
		// This may actually happen if there is no local handler
		// and a previously existing remote handler went away.
		for ( const auto& v : vl)
			Unref(v);

		return;
		}

	// "this" is passed as a cookie for the event
	mgr.QueueEvent(f, std::move(vl), SOURCE_LOCAL,
			a ? a->GetID() : 0, timer_mgr, this);
	}

void Connection::ConnectionEventFast(EventHandlerPtr f, analyzer::Analyzer* a, val_list vl)
	{
	// "this" is passed as a cookie for the event
	mgr.QueueEventFast(f, std::move(vl), SOURCE_LOCAL,
			a ? a->GetID() : 0, timer_mgr, this);
	}

void Connection::ConnectionEvent(EventHandlerPtr f, analyzer::Analyzer* a, val_list* vl)
	{
	ConnectionEvent(f, a, std::move(*vl));
	delete vl;
	}

void Connection::Weird(const char* name, const char* addl)
	{
	weird = 1;
	reporter->Weird(this, name, addl ? addl : "");
	}

void Connection::AddTimer(timer_func timer, double t, bool do_expire,
		TimerType type)
	{
	if ( timers_canceled )
		return;

	// If the key is cleared, the connection isn't stored in the connection
	// table anymore and will soon be deleted. We're not installing new
	// timers anymore then.
	if ( ! key_valid )
		return;

	Timer* conn_timer = new ConnectionTimer(this, timer, t, do_expire, type);
	timer_mgr->Add(conn_timer);
	timers.push_back(conn_timer);
	}

void Connection::RemoveTimer(Timer* t)
	{
	timers.remove(t);
	}

void Connection::CancelTimers()
	{
	// We are going to cancel our timers which, in turn, may cause them to
	// call RemoveTimer(), which would then modify the list we're just
	// traversing. Thus, we first make a copy of the list which we then
	// iterate through.
	timer_list tmp(timers.length());
	std::copy(timers.begin(), timers.end(), std::back_inserter(tmp));

	for ( const auto& timer : tmp )
		timer_mgr->Cancel(timer);

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

	Unref(conn_val);
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
		// login_conn is just a casted 'this'.
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

void Connection::SetRootAnalyzer(analyzer::TransportLayerAnalyzer* analyzer, analyzer::pia::PIA* pia)
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
			RecordVal *endp = conn_val->Lookup(is_orig ? 1 : 2)->AsRecordVal();
			endp->Assign(4, val_mgr->GetCount(flow_label));
			}

		if ( connection_flow_label_changed &&
		     (is_orig ? saw_first_orig_packet : saw_first_resp_packet) )
			{
			ConnectionEventFast(connection_flow_label_changed, 0, {
				BuildConnVal(),
				val_mgr->GetBool(is_orig),
				val_mgr->GetCount(my_flow_label),
				val_mgr->GetCount(flow_label),
			});
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
	return ::PermitWeird(weird_state, name, threshold, rate, duration);
	}
