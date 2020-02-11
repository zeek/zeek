// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include "Hash.h"
#include "Val.h"

#include "protocol/conn-size/ConnSize.h"
#include "protocol/icmp/ICMP.h"
#include "protocol/pia/PIA.h"
#include "protocol/stepping-stone/SteppingStone.h"
#include "protocol/tcp/TCP.h"
#include "protocol/udp/UDP.h"

#include "plugin/Manager.h"

#include "protocol/tcp/events.bif.h"

using namespace analyzer;

Manager::ConnIndex::ConnIndex(const IPAddr& _orig, const IPAddr& _resp,
				     uint16_t _resp_p, uint16_t _proto)
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
	: plugin::ComponentManager<analyzer::Tag, analyzer::Component>("Analyzer", "Tag")
	{
	}

Manager::~Manager()
	{
	for ( analyzer_map_by_port::const_iterator i = analyzers_by_port_tcp.begin(); i != analyzers_by_port_tcp.end(); i++ )
		delete i->second;

	for ( analyzer_map_by_port::const_iterator i = analyzers_by_port_udp.begin(); i != analyzers_by_port_udp.end(); i++ )
		delete i->second;

	analyzers_by_port_udp.clear();
	analyzers_by_port_tcp.clear();

	// Clean up expected-connection table.
	while ( conns_by_timeout.size() )
		{
		ScheduledAnalyzer* a = conns_by_timeout.top();
		conns_by_timeout.pop();
		delete a;
		}
	}

void Manager::InitPreScript()
	{
	// Cache these tags.
	analyzer_connsize = GetComponentTag("CONNSIZE");
	analyzer_stepping = GetComponentTag("STEPPINGSTONE");
	analyzer_tcpstats = GetComponentTag("TCPSTATS");
	}

void Manager::InitPostScript()
	{
	auto id = global_scope()->Lookup("Tunnel::vxlan_ports");

	if ( ! (id && id->ID_Val()) )
		reporter->FatalError("Tunnel::vxlan_ports not defined");

	auto table_val = id->ID_Val()->AsTableVal();
	auto port_list = table_val->ConvertToPureList();

	for ( auto i = 0; i < port_list->Length(); ++i )
		vxlan_ports.emplace_back(port_list->Index(i)->AsPortVal()->Port());

	Unref(port_list);
	}

void Manager::DumpDebug()
	{
#ifdef DEBUG
	DBG_LOG(DBG_ANALYZER, "Available analyzers after zeek_init():");
	list<Component*> all_analyzers = GetComponents();
	for ( list<Component*>::const_iterator i = all_analyzers.begin(); i != all_analyzers.end(); ++i )
		DBG_LOG(DBG_ANALYZER, "    %s (%s)", (*i)->Name().c_str(),
			IsEnabled((*i)->Tag()) ? "enabled" : "disabled");

	DBG_LOG(DBG_ANALYZER, " ");
	DBG_LOG(DBG_ANALYZER, "Analyzers by port:");

	for ( analyzer_map_by_port::const_iterator i = analyzers_by_port_tcp.begin(); i != analyzers_by_port_tcp.end(); i++ )
		{
		string s;

		for ( tag_set::const_iterator j = i->second->begin(); j != i->second->end(); j++ )
			s += string(GetComponentName(*j)) + " ";

		DBG_LOG(DBG_ANALYZER, "    %d/tcp: %s", i->first, s.c_str());
		}

	for ( analyzer_map_by_port::const_iterator i = analyzers_by_port_udp.begin(); i != analyzers_by_port_udp.end(); i++ )
		{
		string s;

		for ( tag_set::const_iterator j = i->second->begin(); j != i->second->end(); j++ )
			s += string(GetComponentName(*j)) + " ";

		DBG_LOG(DBG_ANALYZER, "    %d/udp: %s", i->first, s.c_str());
		}

#endif
	}

void Manager::Done()
	{
	}

bool Manager::EnableAnalyzer(const Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p  )
		return false;

	DBG_LOG(DBG_ANALYZER, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::EnableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p  )
		return false;

	DBG_LOG(DBG_ANALYZER, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::DisableAnalyzer(const Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p  )
		return false;

	DBG_LOG(DBG_ANALYZER, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

bool Manager::DisableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p  )
		return false;

	DBG_LOG(DBG_ANALYZER, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

void Manager::DisableAllAnalyzers()
	{
	DBG_LOG(DBG_ANALYZER, "Disabling all analyzers");

	list<Component*> all_analyzers = GetComponents();
	for ( list<Component*>::const_iterator i = all_analyzers.begin(); i != all_analyzers.end(); ++i )
		(*i)->SetEnabled(false);
	}

analyzer::Tag Manager::GetAnalyzerTag(const char* name)
	{
	return GetComponentTag(name);
	}

bool Manager::IsEnabled(const Tag& tag)
	{
	if ( ! tag )
		return false;

	Component* p = Lookup(tag);

	if ( ! p  )
		return false;

	return p->Enabled();
	}

bool Manager::IsEnabled(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p  )
		return false;

	return p->Enabled();
	}


bool Manager::RegisterAnalyzerForPort(EnumVal* val, PortVal* port)
	{
	Component* p = Lookup(val);

	if ( ! p  )
		return false;

	return RegisterAnalyzerForPort(p->Tag(), port->PortType(), port->Port());
	}

bool Manager::UnregisterAnalyzerForPort(EnumVal* val, PortVal* port)
	{
	Component* p = Lookup(val);

	if ( ! p  )
		return false;

	return UnregisterAnalyzerForPort(p->Tag(), port->PortType(), port->Port());
	}

bool Manager::RegisterAnalyzerForPort(const Tag& tag, TransportProto proto, uint32_t port)
	{
	tag_set* l = LookupPort(proto, port, true);

	if ( ! l )
		return false;

#ifdef DEBUG
	const char* name = GetComponentName(tag).c_str();
	DBG_LOG(DBG_ANALYZER, "Registering analyzer %s for port %" PRIu32 "/%d", name, port, proto);
#endif

	l->insert(tag);
	return true;
	}

bool Manager::UnregisterAnalyzerForPort(const Tag& tag, TransportProto proto, uint32_t port)
	{
	tag_set* l = LookupPort(proto, port, true);

	if ( ! l )
		return true;  // still a "successful" unregistration

#ifdef DEBUG
	const char* name = GetComponentName(tag).c_str();
	DBG_LOG(DBG_ANALYZER, "Unregistering analyzer %s for port %" PRIu32 "/%d", name, port, proto);
#endif

	l->erase(tag);
	return true;
	}

Analyzer* Manager::InstantiateAnalyzer(const Tag& tag, Connection* conn)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->InternalWarning("request to instantiate unknown analyzer");
		return 0;
		}

	if ( ! c->Enabled() )
		return 0;

	if ( ! c->Factory() )
		{
		reporter->InternalWarning("analyzer %s cannot be instantiated dynamically",
					  GetComponentName(tag).c_str());
		return 0;
		}

	Analyzer* a = c->Factory()(conn);

	if ( ! a )
		{
		reporter->InternalWarning("analyzer instantiation failed");
		return 0;
		}

	a->SetAnalyzerTag(tag);

	return a;
	}

Analyzer* Manager::InstantiateAnalyzer(const char* name, Connection* conn)
	{
	Tag tag = GetComponentTag(name);
	return tag ? InstantiateAnalyzer(tag, conn) : 0;
	}

Manager::tag_set* Manager::LookupPort(TransportProto proto, uint32_t port, bool add_if_not_found)
	{
	analyzer_map_by_port* m = 0;

	switch ( proto ) {
	case TRANSPORT_TCP:
		m = &analyzers_by_port_tcp;
		break;

	case TRANSPORT_UDP:
		m = &analyzers_by_port_udp;
		break;

	default:
		reporter->InternalWarning("unsupported transport protocol in analyzer::Manager::LookupPort");
		return 0;
	}

	analyzer_map_by_port::const_iterator i = m->find(port);

	if ( i != m->end() )
		return i->second;

	if ( ! add_if_not_found )
		return 0;

	tag_set* l = new tag_set;
	m->insert(std::make_pair(port, l));
	return l;
	}

Manager::tag_set* Manager::LookupPort(PortVal* val, bool add_if_not_found)
	{
	return LookupPort(val->PortType(), val->Port(), add_if_not_found);
	}

bool Manager::BuildInitialAnalyzerTree(Connection* conn)
	{
	tcp::TCP_Analyzer* tcp = 0;
	udp::UDP_Analyzer* udp = 0;
	icmp::ICMP_Analyzer* icmp = 0;
	TransportLayerAnalyzer* root = 0;
	pia::PIA* pia = 0;
	bool check_port = false;

	switch ( conn->ConnTransport() ) {

	case TRANSPORT_TCP:
		root = tcp = new tcp::TCP_Analyzer(conn);
		pia = new pia::PIA_TCP(conn);
		check_port = true;
		DBG_ANALYZER(conn, "activated TCP analyzer");
		break;

	case TRANSPORT_UDP:
		root = udp = new udp::UDP_Analyzer(conn);
		pia = new pia::PIA_UDP(conn);
		check_port = true;
		DBG_ANALYZER(conn, "activated UDP analyzer");
		break;

	case TRANSPORT_ICMP: {
		root = icmp = new icmp::ICMP_Analyzer(conn);
		DBG_ANALYZER(conn, "activated ICMP analyzer");
		break;
		}

	default:
		reporter->InternalWarning("unknown protocol can't build analyzer tree");
		return false;
	}

	bool scheduled = ApplyScheduledAnalyzers(conn, false, root);

	// Hmm... Do we want *just* the expected analyzer, or all
	// other potential analyzers as well?  For now we only take
	// the scheduled ones.
	if ( ! scheduled )
		{ // Let's see if it's a port we know.
		if ( check_port && ! dpd_ignore_ports )
			{
			int resp_port = ntohs(conn->RespPort());
			tag_set* ports = LookupPort(conn->ConnTransport(), resp_port, false);

			if ( ports )
				{
				for ( tag_set::const_iterator j = ports->begin(); j != ports->end(); ++j )
					{
					Analyzer* analyzer = analyzer_mgr->InstantiateAnalyzer(*j, conn);

					if ( ! analyzer )
						continue;

					root->AddChildAnalyzer(analyzer, false);
					DBG_ANALYZER_ARGS(conn, "activated %s analyzer due to port %d",
							  analyzer_mgr->GetComponentName(*j).c_str(), resp_port);
					}
				}
			}
		}

	if ( tcp )
		{
		// We have to decide whether to reassamble the stream.
		// We turn it on right away if we already have an app-layer
		// analyzer, reassemble_first_packets is true, or the user
		// asks us to do so.  In all other cases, reassembly may
		// be turned on later by the TCP PIA.

		bool reass = root->GetChildren().size() ||
				dpd_reassemble_first_packets ||
				tcp_content_deliver_all_orig ||
				tcp_content_deliver_all_resp;

		if ( tcp_contents && ! reass )
			{
			auto dport = val_mgr->GetPort(ntohs(conn->RespPort()), TRANSPORT_TCP);
			Val* result;

			if ( ! reass )
				reass = tcp_content_delivery_ports_orig->Lookup(dport);

			if ( ! reass )
				reass = tcp_content_delivery_ports_resp->Lookup(dport);

			Unref(dport);
			}

		if ( reass )
			tcp->EnableReassembly();

		if ( IsEnabled(analyzer_stepping) )
			{
			// Add a SteppingStone analyzer if requested.  The port
			// should really not be hardcoded here, but as it can
			// handle non-reassembled data, it doesn't really fit into
			// our general framing ...  Better would be to turn it
			// on *after* we discover we have interactive traffic.
			uint16_t resp_port = ntohs(conn->RespPort());
			if ( resp_port == 22 || resp_port == 23 || resp_port == 513 )
				{
				AddrVal src(conn->OrigAddr());
				if ( ! stp_skip_src->Lookup(&src) )
					tcp->AddChildAnalyzer(new stepping_stone::SteppingStone_Analyzer(conn), false);
				}
			}

		if ( IsEnabled(analyzer_tcpstats) )
			// Add TCPStats analyzer. This needs to see packets so
			// we cannot add it as a normal child.
			tcp->AddChildPacketAnalyzer(new tcp::TCPStats_Analyzer(conn));

		if ( IsEnabled(analyzer_connsize) )
			// Add ConnSize analyzer. Needs to see packets, not stream.
			tcp->AddChildPacketAnalyzer(new conn_size::ConnSize_Analyzer(conn));
		}

	else
		{
		if ( IsEnabled(analyzer_connsize) )
			// Add ConnSize analyzer. Needs to see packets, not stream.
			root->AddChildAnalyzer(new conn_size::ConnSize_Analyzer(conn));
		}

	if ( pia )
		root->AddChildAnalyzer(pia->AsAnalyzer());

	conn->SetRootAnalyzer(root, pia);
	root->Init();
	root->InitChildren();

	PLUGIN_HOOK_VOID(HOOK_SETUP_ANALYZER_TREE, HookSetupAnalyzerTree(conn));

	return true;
	}

void Manager::ExpireScheduledAnalyzers()
	{
	if ( ! network_time )
		return;

	while ( conns_by_timeout.size() )
		{
		ScheduledAnalyzer* a = conns_by_timeout.top();

		if ( a->timeout > network_time )
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

void Manager::ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp,
			uint16_t resp_p,
			TransportProto proto, const Tag& analyzer,
			double timeout)
	{
	if ( ! network_time )
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
	a->timeout = network_time + timeout;

	conns.insert(std::make_pair(a->conn, a));
	conns_by_timeout.push(a);
	}

void Manager::ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp,
			uint16_t resp_p,
			TransportProto proto, const char* analyzer,
			double timeout)
	{
	Tag tag = GetComponentTag(analyzer);

	if ( tag != Tag() )
		ScheduleAnalyzer(orig, resp, resp_p, proto, tag, timeout);
	}

void Manager::ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, PortVal* resp_p,
			       Val* analyzer, double timeout)
	{
	EnumVal* ev = analyzer->AsEnumVal();
	return ScheduleAnalyzer(orig, resp, resp_p->Port(), resp_p->PortType(), Tag(ev), timeout);
	}

Manager::tag_set Manager::GetScheduled(const Connection* conn)
	{
	ConnIndex c(conn->OrigAddr(), conn->RespAddr(),
		    ntohs(conn->RespPort()), conn->ConnTransport());

	std::pair<conns_map::iterator, conns_map::iterator> all = conns.equal_range(c);

	tag_set result;

	for ( conns_map::iterator i = all.first; i != all.second; i++ )
		result.insert(i->second->analyzer);

	// Try wildcard for originator.
	c.orig = IPAddr::v6_unspecified;
	all = conns.equal_range(c);

	for ( conns_map::iterator i = all.first; i != all.second; i++ )
		{
		if ( i->second->timeout > network_time )
			result.insert(i->second->analyzer);
		}

	// We don't delete scheduled analyzers here. They will be expired
	// eventually.
	return result;
	}

bool Manager::ApplyScheduledAnalyzers(Connection* conn, bool init, TransportLayerAnalyzer* parent)
	{
	if ( ! parent )
		parent = conn->GetRootAnalyzer();

	if ( ! parent )
		return false;

	tag_set expected = GetScheduled(conn);

	for ( tag_set::iterator it = expected.begin(); it != expected.end(); ++it )
		{
		Analyzer* analyzer = analyzer_mgr->InstantiateAnalyzer(*it, conn);

		if ( ! analyzer )
			continue;

		parent->AddChildAnalyzer(analyzer, init);

		EnumVal* tag = it->AsEnumVal();
		Ref(tag);
		conn->Event(scheduled_analyzer_applied, 0, tag);

		DBG_ANALYZER_ARGS(conn, "activated %s analyzer as scheduled",
		                  analyzer_mgr->GetComponentName(*it).c_str());
		}

	return expected.size();
	}
