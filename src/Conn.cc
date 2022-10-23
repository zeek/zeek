// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Conn.h"

#include "zeek/zeek-config.h"

#include <binpac.h>
#include <cctype>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Timer.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/session/Manager.h"

namespace zeek
	{

uint64_t Connection::total_connections = 0;
uint64_t Connection::current_connections = 0;

Connection::Connection(const detail::ConnKey& k, double t, const ConnTuple* id, uint32_t flow,
                       const Packet* pkt)
	: Session(t, connection_timeout, connection_status_update,
              detail::connection_status_update_interval),
	  key(k)
	{
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

	weird = 0;

	suppress_event = 0;

	finished = 0;

	hist_seen = 0;
	history = "";

	adapter = nullptr;
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

	delete adapter;

	--current_connections;
	}

void Connection::CheckEncapsulation(const std::shared_ptr<EncapsulationStack>& arg_encap)
	{
	if ( encapsulation && arg_encap )
		{
		if ( *encapsulation != *arg_encap )
			{
			if ( tunnel_changed &&
			     (zeek::detail::tunnel_max_changes_per_connection == 0 ||
			      tunnel_changes < zeek::detail::tunnel_max_changes_per_connection) )
				{
				tunnel_changes++;
				EnqueueEvent(tunnel_changed, nullptr, GetVal(), arg_encap->ToVal());
				}

			encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
			}
		}

	else if ( encapsulation )
		{
		if ( tunnel_changed )
			{
			EncapsulationStack empty;
			EnqueueEvent(tunnel_changed, nullptr, GetVal(), empty.ToVal());
			}

		encapsulation = nullptr;
		}

	else if ( arg_encap )
		{
		if ( tunnel_changed )
			EnqueueEvent(tunnel_changed, nullptr, GetVal(), arg_encap->ToVal());

		encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
		}
	}

void Connection::Done()
	{
	finished = 1;

	if ( adapter )
		{
		if ( ConnTransport() == TRANSPORT_TCP )
			{
			auto* ta = static_cast<packet_analysis::TCP::TCPSessionAdapter*>(adapter);
			assert(ta->IsAnalyzer("TCP"));
			analyzer::tcp::TCP_Endpoint* to = ta->Orig();
			analyzer::tcp::TCP_Endpoint* tr = ta->Resp();

			packet_analysis::TCP::TCPAnalyzer::GetStats().StateLeft(to->state, tr->state);
			}

		if ( ! adapter->IsFinished() )
			adapter->Done();
		}
	}

void Connection::NextPacket(double t, bool is_orig, const IP_Hdr* ip, int len, int caplen,
                            const u_char*& data, int& record_packet, int& record_content,
                            // arguments for reproducing packets
                            const Packet* pkt)
	{
	run_state::current_timestamp = t;
	run_state::current_pkt = pkt;

	if ( adapter )
		{
		if ( adapter->Skipping() )
			return;

		record_current_packet = record_packet;
		record_current_content = record_content;
		adapter->NextPacket(len, data, is_orig, -1, ip, caplen);
		record_packet = record_current_packet;
		record_content = record_current_content;
		}
	else
		last_time = t;

	run_state::current_timestamp = 0;
	run_state::current_pkt = nullptr;
	}

bool Connection::IsReuse(double t, const u_char* pkt)
	{
	return adapter && adapter->IsReuse(t, pkt);
	}

bool Connection::ScaledHistoryEntry(char code, uint32_t& counter, uint32_t& scaling_threshold,
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

void Connection::HistoryThresholdEvent(EventHandlerPtr e, bool is_orig, uint32_t threshold)
	{
	if ( ! e )
		return;

	if ( threshold == 1 )
		// This will be far and away the most common case,
		// and at this stage it's not a *multiple* instance.
		return;

	EnqueueEvent(e, nullptr, GetVal(), val_mgr->Bool(is_orig), val_mgr->Count(threshold));
	}

const RecordValPtr& Connection::GetVal()
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
		orig_endp->Assign(0, 0);
		orig_endp->Assign(1, 0);
		orig_endp->Assign(4, orig_flow_label);

		const int l2_len = sizeof(orig_l2_addr);
		char null[l2_len]{};

		if ( memcmp(&orig_l2_addr, &null, l2_len) != 0 )
			orig_endp->Assign(5, fmt_mac(orig_l2_addr, l2_len));

		auto resp_endp = make_intrusive<RecordVal>(id::endpoint);
		resp_endp->Assign(0, 0);
		resp_endp->Assign(1, 0);
		resp_endp->Assign(4, resp_flow_label);

		if ( memcmp(&resp_l2_addr, &null, l2_len) != 0 )
			resp_endp->Assign(5, fmt_mac(resp_l2_addr, l2_len));

		conn_val->Assign(0, std::move(id_val));
		conn_val->Assign(1, std::move(orig_endp));
		conn_val->Assign(2, std::move(resp_endp));
		// 3 and 4 are set below.
		conn_val->Assign(5, make_intrusive<TableVal>(id::string_set)); // service
		conn_val->Assign(6, val_mgr->EmptyString()); // history

		if ( ! uid )
			uid.Set(zeek::detail::bits_per_uid);

		conn_val->Assign(7, uid.Base62("C"));

		if ( encapsulation && encapsulation->Depth() > 0 )
			conn_val->Assign(8, encapsulation->ToVal());

		if ( vlan != 0 )
			conn_val->Assign(9, vlan);

		if ( inner_vlan != 0 )
			conn_val->Assign(10, inner_vlan);
		}

	if ( adapter )
		adapter->UpdateConnVal(conn_val.get());

	conn_val->AssignTime(3, start_time); // ###
	conn_val->AssignInterval(4, last_time - start_time);

	if ( ! history.empty() )
		{
		auto v = conn_val->GetFieldAs<StringVal>(6);
		if ( *v != history )
			conn_val->Assign(6, history);
		}

	conn_val->SetOrigin(this);

	return conn_val;
	}

analyzer::Analyzer* Connection::FindAnalyzer(analyzer::ID id)
	{
	return adapter ? adapter->FindChild(id) : nullptr;
	}

analyzer::Analyzer* Connection::FindAnalyzer(const zeek::Tag& tag)
	{
	return adapter ? adapter->FindChild(tag) : nullptr;
	}

analyzer::Analyzer* Connection::FindAnalyzer(const char* name)
	{
	return adapter->FindChild(name);
	}

void Connection::AppendAddl(const char* str)
	{
	const auto& cv = GetVal();

	const char* old = cv->GetFieldAs<StringVal>(6)->CheckString();
	const char* format = *old ? "%s %s" : "%s%s";

	cv->Assign(6, util::fmt(format, old, str));
	}

// Returns true if the character at s separates a version number.
static inline bool is_version_sep(const char* s, const char* end)
	{
	return
		// foo-1.2.3
		(s < end - 1 && ispunct(s[0]) && isdigit(s[1])) ||
		// foo-v1.2.3
		(s < end - 2 && ispunct(s[0]) && tolower(s[1]) == 'v' && isdigit(s[2])) ||
		// foo 1.2.3
		isspace(s[0]);
	}

void Connection::Match(detail::Rule::PatternType type, const u_char* data, int len, bool is_orig,
                       bool bol, bool eol, bool clear_state)
	{
	if ( primary_PIA )
		primary_PIA->Match(type, data, len, is_orig, bol, eol, clear_state);
	}

void Connection::RemovalEvent()
	{
	if ( connection_state_remove )
		EnqueueEvent(connection_state_remove, nullptr, GetVal());
	}

void Connection::Weird(const char* name, const char* addl, const char* source)
	{
	weird = 1;
	reporter->Weird(this, name, addl ? addl : "", source ? source : "");
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

	if ( adapter )
		adapter->FlipRoles();

	analyzer_mgr->ApplyScheduledAnalyzers(this);

	AddHistory('^');
	}

void Connection::Describe(ODesc* d) const
	{
	session::Session::Describe(d);

	switch ( proto )
		{
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
			reporter->InternalWarning("unknown transport in Connection::Describe()");

			break;

		default:
			reporter->InternalError("unhandled transport type in Connection::Describe");
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

void Connection::SetSessionAdapter(packet_analysis::IP::SessionAdapter* aa, analyzer::pia::PIA* pia)
	{
	adapter = aa;
	primary_PIA = pia;
	}

void Connection::CheckFlowLabel(bool is_orig, uint32_t flow_label)
	{
	uint32_t& my_flow_label = is_orig ? orig_flow_label : resp_flow_label;

	if ( my_flow_label != flow_label )
		{
		if ( conn_val )
			{
			RecordVal* endp = conn_val->GetFieldAs<RecordVal>(is_orig ? 1 : 2);
			endp->Assign(4, flow_label);
			}

		if ( connection_flow_label_changed &&
		     (is_orig ? saw_first_orig_packet : saw_first_resp_packet) )
			{
			EnqueueEvent(connection_flow_label_changed, nullptr, GetVal(), val_mgr->Bool(is_orig),
			             val_mgr->Count(my_flow_label), val_mgr->Count(flow_label));
			}

		my_flow_label = flow_label;
		}

	if ( is_orig )
		saw_first_orig_packet = 1;
	else
		saw_first_resp_packet = 1;
	}

bool Connection::PermitWeird(const char* name, uint64_t threshold, uint64_t rate, double duration)
	{
	return detail::PermitWeird(weird_state, name, threshold, rate, duration);
	}

	} // namespace zeek
