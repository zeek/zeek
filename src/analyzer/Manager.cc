// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/Manager.h"

#include "zeek/Hash.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/plugin/Manager.h"

namespace zeek::analyzer
	{

Manager::ConnIndex::ConnIndex(const IPAddr& _orig, const IPAddr& _resp, uint16_t _resp_p,
                              uint16_t _proto)
	{
	if ( _orig == IPAddr::v4_unspecified )
		// don't use the IPv4 mapping, use the literal unspecified address
		// to indicate a wildcard
		orig = IPAddr::v6_unspecified;
	else
		orig = _orig;

	resp = _resp;
	resp_p = _resp_p;
	proto = _proto;
	}

Manager::ConnIndex::ConnIndex()
	{
	orig = resp = IPAddr::v4_unspecified;
	resp_p = 0;
	proto = 0;
	}

bool Manager::ConnIndex::operator<(const ConnIndex& other) const
	{
	if ( orig != other.orig )
		return orig < other.orig;

	if ( resp != other.resp )
		return resp < other.resp;

	if ( proto != other.proto )
		return proto < other.proto;

	if ( resp_p != other.resp_p )
		return resp_p < other.resp_p;

	return false;
	}

Manager::Manager()
	: plugin::ComponentManager<analyzer::Component>("Analyzer", "Tag", "AllAnalyzers")
	{
	}

Manager::~Manager()
	{
	// Clean up expected-connection table.
	while ( conns_by_timeout.size() )
		{
		ScheduledAnalyzer* a = conns_by_timeout.top();
		conns_by_timeout.pop();
		delete a;
		}
	}

void Manager::InitPostScript()
	{
	const auto& id = detail::global_scope()->Find("PacketAnalyzer::VXLAN::vxlan_ports");

	if ( ! (id && id->GetVal()) )
		reporter->FatalError("PacketAnalyzer::VXLAN::vxlan_ports not defined");

	auto table_val = id->GetVal()->AsTableVal();
	auto port_list = table_val->ToPureListVal();

	for ( auto i = 0; i < port_list->Length(); ++i )
		vxlan_ports.emplace_back(port_list->Idx(i)->AsPortVal()->Port());

	for ( const auto& p : pending_analyzers_for_ports )
		{
		if ( ! RegisterAnalyzerForPort(p) )
			reporter->Warning("cannot register analyzer for port %u", std::get<2>(p));
		}

	pending_analyzers_for_ports.clear();

	initialized = true;
	}

void Manager::DumpDebug()
	{
#ifdef DEBUG
	DBG_LOG(DBG_ANALYZER, "Available analyzers after zeek_init():");
	std::list<Component*> all_analyzers = GetComponents();
	for ( std::list<Component*>::const_iterator i = all_analyzers.begin(); i != all_analyzers.end();
	      ++i )
		DBG_LOG(DBG_ANALYZER, "    %s (%s)", (*i)->Name().c_str(),
		        IsEnabled((*i)->Tag()) ? "enabled" : "disabled");

	DBG_LOG(DBG_ANALYZER, " ");
	DBG_LOG(DBG_ANALYZER, "Analyzers by port:");

	if ( packet_analysis::AnalyzerPtr tcp = packet_mgr->GetAnalyzer("TCP") )
		{
		auto* ipba = static_cast<packet_analysis::IP::IPBasedAnalyzer*>(tcp.get());
		ipba->DumpPortDebug();
		}

	if ( packet_analysis::AnalyzerPtr udp = packet_mgr->GetAnalyzer("UDP") )
		{
		auto* ipba = static_cast<packet_analysis::IP::IPBasedAnalyzer*>(udp.get());
		ipba->DumpPortDebug();
		}

#endif
	}

void Manager::Done() { }

bool Manager::EnableAnalyzer(const zeek::Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	DBG_LOG(DBG_ANALYZER, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::EnableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	DBG_LOG(DBG_ANALYZER, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::DisableAnalyzer(const zeek::Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	DBG_LOG(DBG_ANALYZER, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

bool Manager::DisableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	DBG_LOG(DBG_ANALYZER, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

void Manager::DisableAllAnalyzers()
	{
	DBG_LOG(DBG_ANALYZER, "Disabling all analyzers");

	std::list<Component*> all_analyzers = GetComponents();
	for ( std::list<Component*>::const_iterator i = all_analyzers.begin(); i != all_analyzers.end();
	      ++i )
		(*i)->SetEnabled(false);
	}

zeek::Tag Manager::GetAnalyzerTag(const char* name)
	{
	return GetComponentTag(name);
	}

bool Manager::IsEnabled(const zeek::Tag& tag)
	{
	if ( ! tag )
		return false;

	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	return p->Enabled();
	}

bool Manager::IsEnabled(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	return p->Enabled();
	}

bool Manager::RegisterAnalyzerForPort(EnumVal* val, PortVal* port)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	return RegisterAnalyzerForPort(p->Tag(), port->PortType(), port->Port());
	}

bool Manager::UnregisterAnalyzerForPort(EnumVal* val, PortVal* port)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	return UnregisterAnalyzerForPort(p->Tag(), port->PortType(), port->Port());
	}

bool Manager::RegisterAnalyzerForPort(const zeek::Tag& tag, TransportProto proto, uint32_t port)
	{
	if ( initialized )
		return RegisterAnalyzerForPort(std::make_tuple(tag, proto, port));
	else
		{
		// Cannot register these before PostScriptInit() has run because we
		// depend on packet analysis having been set up. That also means we don't have
		// a reliable return value, for now we just assume it's working.
		pending_analyzers_for_ports.emplace(tag, proto, port);
		return true;
		}
	}

bool Manager::RegisterAnalyzerForPort(const std::tuple<zeek::Tag, TransportProto, uint32_t>& p)
	{
	const auto& [tag, proto, port] = p;

	// TODO: this class is becoming more generic and removing a lot of the
	// checks for protocols, but this part might need to stay like this.
	packet_analysis::AnalyzerPtr analyzer;
	if ( proto == TRANSPORT_TCP )
		analyzer = packet_mgr->GetAnalyzer("TCP");
	else if ( proto == TRANSPORT_UDP )
		analyzer = packet_mgr->GetAnalyzer("UDP");

	if ( ! analyzer )
		return false;

	auto* ipba = static_cast<packet_analysis::IP::IPBasedAnalyzer*>(analyzer.get());

	return ipba->RegisterAnalyzerForPort(tag, port);
	}

bool Manager::UnregisterAnalyzerForPort(const zeek::Tag& tag, TransportProto proto, uint32_t port)
	{
	if ( auto i = pending_analyzers_for_ports.find(std::make_tuple(tag, proto, port));
	     i != pending_analyzers_for_ports.end() )
		pending_analyzers_for_ports.erase(i);

	// TODO: this class is becoming more generic and removing a lot of the
	// checks for protocols, but this part might need to stay like this.
	packet_analysis::AnalyzerPtr analyzer;
	if ( proto == TRANSPORT_TCP )
		analyzer = packet_mgr->GetAnalyzer("TCP");
	else if ( proto == TRANSPORT_UDP )
		analyzer = packet_mgr->GetAnalyzer("UDP");

	if ( ! analyzer )
		return false;

	auto* ipba = static_cast<packet_analysis::IP::IPBasedAnalyzer*>(analyzer.get());

	return ipba->UnregisterAnalyzerForPort(tag, port);
	}

Analyzer* Manager::InstantiateAnalyzer(const zeek::Tag& tag, Connection* conn)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->InternalWarning("request to instantiate unknown analyzer");
		return nullptr;
		}

	if ( ! c->Enabled() )
		return nullptr;

	if ( ! c->Factory() )
		{
		reporter->InternalWarning("analyzer %s cannot be instantiated dynamically",
		                          GetComponentName(tag).c_str());
		return nullptr;
		}

	Analyzer* a = c->Factory()(conn);

	if ( ! a )
		{
		reporter->InternalWarning("analyzer instantiation failed");
		return nullptr;
		}

	a->SetAnalyzerTag(tag);

	return a;
	}

Analyzer* Manager::InstantiateAnalyzer(const char* name, Connection* conn)
	{
	zeek::Tag tag = GetComponentTag(name);
	return tag ? InstantiateAnalyzer(tag, conn) : nullptr;
	}

void Manager::ExpireScheduledAnalyzers()
	{
	if ( ! run_state::network_time )
		return;

	while ( conns_by_timeout.size() )
		{
		ScheduledAnalyzer* a = conns_by_timeout.top();

		if ( a->timeout > run_state::network_time )
			return;

		conns_by_timeout.pop();

		std::pair<conns_map::iterator, conns_map::iterator> all = conns.equal_range(a->conn);

		bool found = false;

		for ( conns_map::iterator i = all.first; i != all.second; i++ )
			{
			if ( i->second != a )
				continue;

			conns.erase(i);

			DBG_LOG(DBG_ANALYZER, "Expiring expected analyzer %s for connection %s",
			        analyzer_mgr->GetComponentName(a->analyzer).c_str(),
			        fmt_conn_id(a->conn.orig, 0, a->conn.resp, a->conn.resp_p));

			delete a;
			found = true;
			break;
			}

		assert(found);
		}
	}

void Manager::ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, uint16_t resp_p,
                               TransportProto proto, const zeek::Tag& analyzer, double timeout)
	{
	if ( ! run_state::network_time )
		{
		reporter->Warning("cannot schedule analyzers before processing begins; ignored");
		return;
		}

	assert(timeout);

	// Use the chance to see if the oldest entry is already expired.
	ExpireScheduledAnalyzers();

	ScheduledAnalyzer* a = new ScheduledAnalyzer;
	a->conn = ConnIndex(orig, resp, resp_p, proto);
	a->analyzer = analyzer;
	a->timeout = run_state::network_time + timeout;

	conns.insert(std::make_pair(a->conn, a));
	conns_by_timeout.push(a);
	}

void Manager::ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, uint16_t resp_p,
                               TransportProto proto, const char* analyzer, double timeout)
	{
	zeek::Tag tag = GetComponentTag(analyzer);

	if ( tag != zeek::Tag() )
		ScheduleAnalyzer(orig, resp, resp_p, proto, tag, timeout);
	}

void Manager::ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, PortVal* resp_p,
                               Val* analyzer, double timeout)
	{
	EnumValPtr ev{NewRef{}, analyzer->AsEnumVal()};
	return ScheduleAnalyzer(orig, resp, resp_p->Port(), resp_p->PortType(),
	                        zeek::Tag(std::move(ev)), timeout);
	}

Manager::tag_set Manager::GetScheduled(const Connection* conn)
	{
	ConnIndex c(conn->OrigAddr(), conn->RespAddr(), ntohs(conn->RespPort()), conn->ConnTransport());

	std::pair<conns_map::iterator, conns_map::iterator> all = conns.equal_range(c);

	tag_set result;

	for ( conns_map::iterator i = all.first; i != all.second; i++ )
		result.insert(i->second->analyzer);

	// Try wildcard for originator.
	c.orig = IPAddr::v6_unspecified;
	all = conns.equal_range(c);

	for ( conns_map::iterator i = all.first; i != all.second; i++ )
		{
		if ( i->second->timeout > run_state::network_time )
			result.insert(i->second->analyzer);
		}

	// We don't delete scheduled analyzers here. They will be expired
	// eventually.
	return result;
	}

bool Manager::ApplyScheduledAnalyzers(Connection* conn, bool init,
                                      packet_analysis::IP::SessionAdapter* parent)
	{
	if ( ! parent )
		parent = conn->GetSessionAdapter();

	if ( ! parent )
		return false;

	tag_set expected = GetScheduled(conn);

	for ( tag_set::iterator it = expected.begin(); it != expected.end(); ++it )
		{
		Analyzer* analyzer = analyzer_mgr->InstantiateAnalyzer(*it, conn);

		if ( ! analyzer )
			continue;

		parent->AddChildAnalyzer(analyzer, init);

		if ( scheduled_analyzer_applied )
			conn->EnqueueEvent(scheduled_analyzer_applied, nullptr, conn->GetVal(), it->AsVal());

		DBG_ANALYZER_ARGS(conn, "activated %s analyzer as scheduled",
		                  analyzer_mgr->GetComponentName(*it).c_str());
		}

	return expected.size();
	}

	} // namespace zeek::analyzer
