#include "DPM.h"
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

DPM::DPM()
: expected_conns_queue(AssignedAnalyzer::compare)
	{
	}

DPM::~DPM()
	{
	delete [] active_analyzers;
	}

void DPM::PreScriptInit()
	{
	for ( int i = 1; i < int(AnalyzerTag::LastAnalyzer); i++ )
		{
		// Create IDs ANALYZER_*.
		ID* id = install_ID(fmt("ANALYZER_%s",
				Analyzer::analyzer_configs[i].name),
					GLOBAL_MODULE_NAME, true, false);
		assert(id);
		id->SetVal(new Val(i, TYPE_COUNT));
		id->SetType(id->ID_Val()->Type()->Ref());
		}
	}

void DPM::PostScriptInit()
	{
	active_analyzers = new bool[int(AnalyzerTag::LastAnalyzer)];

	for ( int i = 1; i < int(AnalyzerTag::LastAnalyzer); i++ )
		{
		if ( ! Analyzer::analyzer_configs[i].available )
			continue;

		active_analyzers[i] = Analyzer::analyzer_configs[i].available();
		if ( active_analyzers[i] )
			AddConfig(Analyzer::analyzer_configs[i]);
		}
	}

void DPM::AddConfig(const Analyzer::Config& cfg)
	{
#ifdef USE_PERFTOOLS_DEBUG
	HeapLeakChecker::Disabler disabler;
#endif

	Val* index = new Val(cfg.tag, TYPE_COUNT);
	Val* v = dpd_config->Lookup(index);

#ifdef DEBUG
	ODesc desc;
#endif
	if ( v )
		{
		RecordVal* cfg_record = v->AsRecordVal();
		Val* ports = cfg_record->Lookup(0);

		if ( ports )
			{
			ListVal* plist = ports->AsTableVal()->ConvertToPureList();

			for ( int i = 0; i< plist->Length(); ++i )
				{
				PortVal* port = plist->Index(i)->AsPortVal();

				analyzer_map* ports =
					port->IsTCP() ? &tcp_ports : &udp_ports;

				analyzer_map::iterator j =
					ports->find(port->Port());

				if ( j == ports->end() )
					{
					tag_list* analyzers = new tag_list;
					analyzers->push_back(cfg.tag);
					ports->insert(analyzer_map::value_type(port->Port(), analyzers));
					}
				else
					j->second->push_back(cfg.tag);

#ifdef DEBUG
				port->Describe(&desc);
				desc.SP();
#endif
				}
			}
		}

	DBG_LOG(DBG_DPD, "%s analyzer active on port(s) %s", cfg.name, desc.Description());

	Unref(index);
	}

AnalyzerTag::Tag DPM::GetExpected(int proto, const Connection* conn)
	{
	if ( ! expected_conns.Length() )
		return AnalyzerTag::Error;

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
		return AnalyzerTag::Error;

	// We don't delete it here.  It will be expired eventually.
	return a->analyzer;
	}

bool DPM::BuildInitialAnalyzerTree(TransportProto proto, Connection* conn,
					const u_char* data)
	{
	TCP_Analyzer* tcp = 0;
	UDP_Analyzer* udp = 0;
	ICMP_Analyzer* icmp = 0;
	TransportLayerAnalyzer* root = 0;
	AnalyzerTag::Tag expected = AnalyzerTag::Error;
	analyzer_map* ports = 0;
	PIA* pia = 0;
	bool analyzed = false;

	switch ( proto ) {

	case TRANSPORT_TCP:
		root = tcp = new TCP_Analyzer(conn);
		pia = new PIA_TCP(conn);
		expected = GetExpected(proto, conn);
		ports = &tcp_ports;
		DBG_DPD(conn, "activated TCP analyzer");
		break;

	case TRANSPORT_UDP:
		root = udp = new UDP_Analyzer(conn);
		pia = new PIA_UDP(conn);
		expected = GetExpected(proto, conn);
		ports = &udp_ports;
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
	if ( expected != AnalyzerTag::Error )
		{
		Analyzer* analyzer =
			Analyzer::InstantiateAnalyzer(expected, conn);
		root->AddChildAnalyzer(analyzer, false);
		DBG_DPD_ARGS(conn, "activated %s analyzer as scheduled",
			Analyzer::GetTagName(expected));

		// Hmm... Do we want *just* the expected analyzer, or all
		// other potential analyzers as well?  For now we only take
		// the scheduled one.
		}

	else
		{ // Let's see if it's a port we know.
		if ( ports && ! dpd_ignore_ports )
			{
			analyzer_map::const_iterator i =
				ports->find(ntohs(conn->RespPort()));

			if ( i != ports->end() )
				{
				tag_list* analyzers = i->second;
				for ( tag_list::const_iterator j = analyzers->begin();
				      j != analyzers->end(); j++ )
					{
					Analyzer* analyzer =
					Analyzer::InstantiateAnalyzer(*j, conn);

					root->AddChildAnalyzer(analyzer, false);
					DBG_DPD_ARGS(conn, "activated %s analyzer due to port %d", Analyzer::GetTagName(*j), conn->RespPort());
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

		// Add a BackDoor analyzer if requested.  This analyzer
		// can handle both reassembled and non-reassembled input.
		if ( BackDoor_Analyzer::Available() )
			{
			BackDoor_Analyzer* bd = new BackDoor_Analyzer(conn);
			tcp->AddChildAnalyzer(bd, false);
			}

		// Add a InterConn analyzer if requested.  This analyzer
		// can handle both reassembled and non-reassembled input.
		if ( InterConn_Analyzer::Available() )
			{
			InterConn_Analyzer* bd = new InterConn_Analyzer(conn);
			tcp->AddChildAnalyzer(bd, false);
			}

		// Add a SteppingStone analyzer if requested.  The port
		// should really not be hardcoded here, but as it can
		// handle non-reassembled data, it doesn't really fit into
		// our general framing ...  Better would be to turn it
		// on *after* we discover we have interactive traffic.
		uint16 resp_port = ntohs(conn->RespPort());
		if ( SteppingStone_Analyzer::Available() &&
		     (resp_port == 22 || resp_port == 23 || resp_port == 513) )
			{
			AddrVal src(conn->OrigAddr());
			if ( ! stp_skip_src->Lookup(&src) )
				{
				SteppingStone_Analyzer* bd =
					new SteppingStone_Analyzer(conn);
				tcp->AddChildAnalyzer(bd, false);
				}
			}

		// Add TCPStats analyzer. This needs to see packets so
		// we cannot add it as a normal child.
		if ( TCPStats_Analyzer::Available() )
			tcp->AddChildPacketAnalyzer(new TCPStats_Analyzer(conn));

		// Add ConnSize analyzer. Needs to see packets, not stream.
		if ( ConnSize_Analyzer::Available() )
			tcp->AddChildPacketAnalyzer(new ConnSize_Analyzer(conn));
		}

	else
		{
		if ( ConnSize_Analyzer::Available() )
			root->AddChildAnalyzer(new ConnSize_Analyzer(conn), false);
		}

	if ( pia )
		root->AddChildAnalyzer(pia->AsAnalyzer(), false);

	if ( root->GetChildren().size() )
		analyzed = true;

	conn->SetRootAnalyzer(root, pia);
	root->Init();
	root->InitChildren();

	if ( ! analyzed )
		conn->SetLifetime(non_analyzed_lifetime);

	if ( expected != AnalyzerTag::Error  )
		conn->Event(expected_connection_seen, 0,
				new Val(expected, TYPE_COUNT));

	return true;
	}

void DPM::ExpectConnection(const IPAddr& orig, const IPAddr& resp,
			uint16 resp_p,
			TransportProto proto, AnalyzerTag::Tag analyzer,
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
				Analyzer::GetTagName(analyzer),
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

void DPM::Done()
	{
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

