
#include "Manager.h"

#include "PIA.h"
#include "Hash.h"
#include "ICMP.h"
#include "UDP.h"
#include "TCP.h"
#include "Val.h"
#include "BackDoor.h"
#include "InterConn.h"
#include "SteppingStone.h"
#include "ConnSizeAnalyzer.h"

#include "plugin/Manager.h"

using namespace analyzer;

ExpectedConn::ExpectedConn(const IPAddr& _orig, const IPAddr& _resp,
				uint16 _resp_p, uint16 _proto)
	{
	if ( _orig == IPAddr(string("0.0.0.0")) )
		// don't use the IPv4 mapping, use the literal unspecified address
		// to indicate a wildcard
		orig = IPAddr(string("::"));
	else
		orig = _orig;
	resp = _resp;
	resp_p = _resp_p;
	proto = _proto;
	}

ExpectedConn::ExpectedConn(const ExpectedConn& c)
	{
	orig = c.orig;
	resp = c.resp;
	resp_p = c.resp_p;
	proto = c.proto;
	}

Manager::Manager()
	: expected_conns_queue(AssignedAnalyzer::compare)
	{
	tag_enum_type = new EnumType("Analyzer::Tag");
	::ID* id = install_ID("Tag", "Analyzer", true, true);
	add_type(id, tag_enum_type, 0, 0);
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
	while ( expected_conns_queue.size() )
		{
		AssignedAnalyzer* a = expected_conns_queue.top();
		if ( ! a->deleted )
			{
			HashKey* key = BuildExpectedConnHashKey(a->conn);
			expected_conns.Remove(key);
			delete key;
			}

		expected_conns_queue.pop();
		delete a;
		}
	}

void Manager::Init()
	{
	std::list<PluginComponent*> analyzers = plugin_mgr->Components<PluginComponent>(plugin::component::ANALYZER);

	for ( std::list<PluginComponent*>::const_iterator i = analyzers.begin(); i != analyzers.end(); i++ )
		RegisterAnalyzerComponent(*i);

	// Caache these tags.
	analyzer_backdoor = GetAnalyzerTag("BACKDOOR");
	analyzer_connsize = GetAnalyzerTag("CONNSIZE");
	analyzer_interconn = GetAnalyzerTag("INTERCONN");
	analyzer_stepping = GetAnalyzerTag("STEPPINGSTONE");
	analyzer_tcpstats = GetAnalyzerTag("TCPSTATS");
	}

void Manager::DumpDebug()
	{
#ifdef DEBUG
	DBG_LOG(DBG_DPD, "Available analyzers after bro_init():");
	for ( analyzer_map_by_name::const_iterator i = analyzers_by_name.begin(); i != analyzers_by_name.end(); i++ )
		DBG_LOG(DBG_DPD, "    %s (%s)", i->second->Name().c_str(), IsEnabled(i->second->Tag()) ? "enabled" : "disabled");

	DBG_LOG(DBG_DPD, "");
	DBG_LOG(DBG_DPD, "Analyzers by port:");

	for ( analyzer_map_by_port::const_iterator i = analyzers_by_port_tcp.begin(); i != analyzers_by_port_tcp.end(); i++ )
		{
		string s;

		for ( tag_set::const_iterator j = i->second->begin(); j != i->second->end(); j++ )
			s += GetAnalyzerName(*j) + " ";

		DBG_LOG(DBG_DPD, "    %d/tcp: %s", i->first, s.c_str());
		}

	for ( analyzer_map_by_port::const_iterator i = analyzers_by_port_udp.begin(); i != analyzers_by_port_udp.end(); i++ )
		{
		string s;

		for ( tag_set::const_iterator j = i->second->begin(); j != i->second->end(); j++ )
			s += GetAnalyzerName(*j) + " ";

		DBG_LOG(DBG_DPD, "    %d/udp: %s", i->first, s.c_str());
		}

#if 0
	ODesc d;
	tag_enum_type->Describe(&d);

	DBG_LOG(DBG_DPD, "");
	DBG_LOG(DBG_DPD, "Analyzer::Tag type: %s", d.Description());
#endif

#endif
	}

void Manager::Done()
	{
	}

void Manager::RegisterAnalyzerComponent(PluginComponent* component)
	{
	if ( Lookup(component->Name()) )
		reporter->FatalError("Analyzer %s defined more than once", component->Name().c_str());

	DBG_LOG(DBG_DPD, "Registering analyzer %s (tag %s)",
		component->Name().c_str(), component->Tag().AsString().c_str());

	analyzers_by_name.insert(std::make_pair(component->Name(), component));
	analyzers_by_tag.insert(std::make_pair(component->Tag(), component));
	analyzers_by_val.insert(std::make_pair(component->Tag().Val()->InternalInt(), component));

	// Install enum "Analyzer::ANALYZER_*"
	string name = to_upper(component->Name());
	string id = fmt("ANALYZER_%s", name.c_str());
	tag_enum_type->AddName("Analyzer", id.c_str(), component->Tag().Val()->InternalInt(), true);
	}

bool Manager::EnableAnalyzer(Tag tag)
	{
	PluginComponent* p = Lookup(tag);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to enable non-existing analyzer");
		return false;
		}

	DBG_LOG(DBG_DPD, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::EnableAnalyzer(EnumVal* val)
	{
	PluginComponent* p = Lookup(val);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to enable non-existing analyzer");
		return false;
		}

	DBG_LOG(DBG_DPD, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::DisableAnalyzer(Tag tag)
	{
	PluginComponent* p = Lookup(tag);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to disable non-existing analyzer");
		return false;
		}

	DBG_LOG(DBG_DPD, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

bool Manager::DisableAnalyzer(EnumVal* val)
	{
	PluginComponent* p = Lookup(val);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to disable non-existing analyzer");
		return false;
		}

	DBG_LOG(DBG_DPD, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

bool Manager::IsEnabled(Tag tag)
	{
	if ( ! tag )
		return false;

	PluginComponent* p = Lookup(tag);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to check non-existing analyzer");
		return false;
		}

	return p->Enabled();
	}

bool Manager::IsEnabled(EnumVal* val)
	{
	PluginComponent* p = Lookup(val);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to check non-existing analyzer");
		return false;
		}

	return p->Enabled();
	}


bool Manager::RegisterAnalyzerForPort(EnumVal* val, PortVal* port)
	{
	PluginComponent* p = Lookup(val);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to register port for non-existing analyzer");
		return false;
		}

	return RegisterAnalyzerForPort(p->Tag(), port->PortType(), port->Port());
	}

bool Manager::UnregisterAnalyzerForPort(EnumVal* val, PortVal* port)
	{
	PluginComponent* p = Lookup(val);

	if ( ! p  )
		{
		DBG_LOG(DBG_DPD, "Asked to unregister port fork non-existing analyzer");
		return false;
		}

	return UnregisterAnalyzerForPort(p->Tag(), port->PortType(), port->Port());
	}

bool Manager::RegisterAnalyzerForPort(Tag tag, TransportProto proto, uint32 port)
	{
	tag_set* l = LookupPort(proto, port, true);

#ifdef DEBUG
	std::string name = GetAnalyzerName(tag);
	DBG_LOG(DBG_DPD, "Registering analyzer %s for port %" PRIu32 "/%d", name.c_str(), port, proto);
#endif

	l->insert(tag);
	return true;
	}

bool Manager::UnregisterAnalyzerForPort(Tag tag, TransportProto proto, uint32 port)
	{
	tag_set* l = LookupPort(proto, port, true);

#ifdef DEBUG
	std::string name = GetAnalyzerName(tag);
	DBG_LOG(DBG_DPD, "Unregistering analyzer %s for port %" PRIu32 "/%d", name.c_str(), port, proto);
#endif

	l->erase(tag);
	return true;
	}

Analyzer* Manager::InstantiateAnalyzer(Tag tag, Connection* conn)
	{
	PluginComponent* c = Lookup(tag);

	if ( ! c )
		reporter->InternalError("request to instantiate unknown analyzer");

	if ( ! c->Enabled() )
		return 0;

	assert(c->Factory());
	Analyzer* a = c->Factory()(conn);

	if ( ! a )
		reporter->InternalError("analyzer instantiation failed");

	return a;
	}

string Manager::GetAnalyzerName(Tag tag)
	{
	if ( ! tag )
		return "<error>";

	PluginComponent* c = Lookup(tag);

	if ( ! c )
		reporter->InternalError("request for name of unknown analyzer tag %s", tag.AsString().c_str());

	return c->Name();
	}

string Manager::GetAnalyzerName(Val* val)
	{
	return GetAnalyzerName(Tag(val->AsEnumVal()));
	}

Tag Manager::GetAnalyzerTag(const string& name)
	{
	PluginComponent* c = Lookup(name);
	return c ? c->Tag() : Tag::ERROR;
	}

Tag Manager::GetAnalyzerTag(const char* name)
	{
	PluginComponent* c = Lookup(name);
	return c ? c->Tag() : Tag::ERROR;
	}

EnumType* Manager::GetTagEnumType()
	{
	return tag_enum_type;
	}


PluginComponent* Manager::Lookup(const string& name)
	{
	analyzer_map_by_name::const_iterator i = analyzers_by_name.find(name);
	return i != analyzers_by_name.end() ? i->second : 0;
	}

PluginComponent* Manager::Lookup(const char* name)
	{
	analyzer_map_by_name::const_iterator i = analyzers_by_name.find(name);
	return i != analyzers_by_name.end() ? i->second : 0;
	}

PluginComponent* Manager::Lookup(const Tag& tag)
	{
	analyzer_map_by_tag::const_iterator i = analyzers_by_tag.find(tag);
	return i != analyzers_by_tag.end() ? i->second : 0;
	}

PluginComponent* Manager::Lookup(EnumVal* val)
	{
	analyzer_map_by_val::const_iterator i = analyzers_by_val.find(val->InternalInt());
	return i != analyzers_by_val.end() ? i->second : 0;
	}

Manager::tag_set* Manager::LookupPort(TransportProto proto, uint32 port, bool add_if_not_found)
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
		reporter->InternalError("unsupport transport protocol in analyzer::Manager::LookupPort");
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

Tag Manager::GetExpected(int proto, const Connection* conn)
	{
	if ( ! expected_conns.Length() )
		return Tag::ERROR;

	ExpectedConn c(conn->OrigAddr(), conn->RespAddr(),
			ntohs(conn->RespPort()), proto);

	HashKey* key = BuildExpectedConnHashKey(c);
	AssignedAnalyzer* a = expected_conns.Lookup(key);
	delete key;

	if ( ! a )
		{
		// Wildcard for originator.
		c.orig = IPAddr(string("::"));

		HashKey* key = BuildExpectedConnHashKey(c);
		a = expected_conns.Lookup(key);
		delete key;
		}

	if ( ! a )
		return Tag::ERROR;

	// We don't delete it here.  It will be expired eventually.
	return a->analyzer;
	}

bool Manager::BuildInitialAnalyzerTree(TransportProto proto, Connection* conn,
					const u_char* data)
	{
	Analyzer* analyzer = 0;
	TCP_Analyzer* tcp = 0;
	UDP_Analyzer* udp = 0;
	ICMP_Analyzer* icmp = 0;
	TransportLayerAnalyzer* root = 0;
	Tag expected = Tag::ERROR;
	PIA* pia = 0;
	bool analyzed = false;
	bool check_port = false;

	switch ( proto ) {

	case TRANSPORT_TCP:
		root = tcp = new TCP_Analyzer(conn);
		pia = new PIA_TCP(conn);
		expected = GetExpected(proto, conn);
		check_port = true;
		DBG_DPD(conn, "activated TCP analyzer");
		break;

	case TRANSPORT_UDP:
		root = udp = new UDP_Analyzer(conn);
		pia = new PIA_UDP(conn);
		expected = GetExpected(proto, conn);
		check_port = true;
		DBG_DPD(conn, "activated UDP analyzer");
		break;

	case TRANSPORT_ICMP: {
		root = icmp = new ICMP_Analyzer(conn);
		DBG_DPD(conn, "activated ICMP analyzer");
		analyzed = true;
		break;
		}

	default:
		reporter->InternalError("unknown protocol");
	}

	if ( ! root )
		{
		DBG_DPD(conn, "cannot build analyzer tree");
		return false;
		}

	// Any scheduled analyzer?
	if ( expected )
		{
		Analyzer* analyzer = analyzer_mgr->InstantiateAnalyzer(expected, conn);

		if ( analyzer )
			{
			root->AddChildAnalyzer(analyzer, false);

			DBG_DPD_ARGS(conn, "activated %s analyzer as scheduled",
				     analyzer_mgr->GetAnalyzerName(expected).c_str());
			}

		// Hmm... Do we want *just* the expected analyzer, or all
		// other potential analyzers as well?  For now we only take
		// the scheduled one.
		}

	else
		{ // Let's see if it's a port we know.
		if ( check_port && ! dpd_ignore_ports )
			{
			int resp_port = ntohs(conn->RespPort());
			tag_set* ports = LookupPort(proto, resp_port, false);

			if ( ports )
				{
				for ( tag_set::const_iterator j = ports->begin(); j != ports->end(); ++j )
					{
					Analyzer* analyzer = analyzer_mgr->InstantiateAnalyzer(*j, conn);

					if ( ! analyzer )
						continue;

					root->AddChildAnalyzer(analyzer, false);
					DBG_DPD_ARGS(conn, "activated %s analyzer due to port %d",
						     analyzer_mgr->GetAnalyzerName(*j).c_str(), resp_port);
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
			PortVal dport(ntohs(conn->RespPort()), TRANSPORT_TCP);
			Val* result;

			if ( ! reass )
				reass = tcp_content_delivery_ports_orig->Lookup(&dport);

			if ( ! reass )
				reass = tcp_content_delivery_ports_resp->Lookup(&dport);
			}

		if ( reass )
			tcp->EnableReassembly();

		if ( IsEnabled(analyzer_backdoor) )
			// Add a BackDoor analyzer if requested.  This analyzer
			// can handle both reassembled and non-reassembled input.
			tcp->AddChildAnalyzer(new BackDoor_Analyzer(conn), false);

		if ( IsEnabled(analyzer_interconn) )
			// Add a InterConn analyzer if requested.  This analyzer
			// can handle both reassembled and non-reassembled input.
			tcp->AddChildAnalyzer(new InterConn_Analyzer(conn), false);

		if ( IsEnabled(analyzer_stepping) )
			{
			// Add a SteppingStone analyzer if requested.  The port
			// should really not be hardcoded here, but as it can
			// handle non-reassembled data, it doesn't really fit into
			// our general framing ...  Better would be to turn it
			// on *after* we discover we have interactive traffic.
			uint16 resp_port = ntohs(conn->RespPort());
			if ( resp_port == 22 || resp_port == 23 || resp_port == 513 )
				{
				AddrVal src(conn->OrigAddr());
				if ( ! stp_skip_src->Lookup(&src) )
					tcp->AddChildAnalyzer(new SteppingStone_Analyzer(conn), false);
				}
			}

		if ( IsEnabled(analyzer_tcpstats) )
			// Add TCPStats analyzer. This needs to see packets so
			// we cannot add it as a normal child.
			tcp->AddChildPacketAnalyzer(new TCPStats_Analyzer(conn));

		if ( IsEnabled(analyzer_connsize) )
			// Add ConnSize analyzer. Needs to see packets, not stream.
			tcp->AddChildPacketAnalyzer(new ConnSize_Analyzer(conn));
		}

	else
		{
		if ( IsEnabled(analyzer_connsize) )
			// Add ConnSize analyzer. Needs to see packets, not stream.
			udp->AddChildAnalyzer(new ConnSize_Analyzer(conn));
		}

	if ( pia )
		root->AddChildAnalyzer(pia->AsAnalyzer());

	if ( root->GetChildren().size() )
		analyzed = true;

	conn->SetRootAnalyzer(root, pia);
	root->Init();
	root->InitChildren();

	if ( ! analyzed )
		conn->SetLifetime(non_analyzed_lifetime);

	if ( expected != Tag::ERROR  )
		conn->Event(expected_connection_seen, 0,
				new Val(expected, TYPE_COUNT));

	return true;
	}

void Manager::ExpectConnection(const IPAddr& orig, const IPAddr& resp,
			uint16 resp_p,
			TransportProto proto, Tag analyzer,
			double timeout, void* cookie)
	{
	// Use the chance to see if the oldest entry is already expired.
	if ( expected_conns_queue.size() )
		{
		AssignedAnalyzer* a = expected_conns_queue.top();
		if ( a->timeout < network_time )
			{
			if ( ! a->deleted )
				{
				HashKey* key = BuildExpectedConnHashKey(a->conn);
				expected_conns.Remove(key);
				delete key;
				}

			expected_conns_queue.pop();

			DBG_LOG(DBG_DPD, "Expired expected %s analyzer for %s",
				analyzer_mgr->GetAnalyzerName(analyzer).c_str(),
				fmt_conn_id(a->conn.orig, 0,
						a->conn.resp,
						a->conn.resp_p));

			delete a;
			}
		}

	ExpectedConn c(orig, resp, resp_p, proto);

	HashKey* key = BuildExpectedConnHashKey(c);

	AssignedAnalyzer* a = expected_conns.Lookup(key);

	if ( a )
		a->deleted = true;

	a = new AssignedAnalyzer(c);

	a->analyzer = analyzer;
	a->cookie = cookie;
	a->timeout = network_time + timeout;
	a->deleted = false;

	expected_conns.Insert(key, a);
	expected_conns_queue.push(a);
	delete key;
	}

void Manager::ExpectConnection(const IPAddr& orig, const IPAddr& resp,
			uint16 resp_p,
			TransportProto proto, const string& analyzer,
			double timeout, void* cookie)
	{
	Tag tag = GetAnalyzerTag(analyzer);

	if ( tag != Tag::ERROR )
		ExpectConnection(orig, resp, resp_p, proto, tag, timeout, cookie);
	}

void Manager::ExpectConnection(const IPAddr& orig, const IPAddr& resp, PortVal* resp_p,
			       Val* analyzer, double timeout, void* cookie)
	{
	EnumVal* ev = analyzer->AsEnumVal();
	return ExpectConnection(orig, resp, resp_p->Port(), resp_p->PortType(), Tag(ev), timeout, cookie);
	}
