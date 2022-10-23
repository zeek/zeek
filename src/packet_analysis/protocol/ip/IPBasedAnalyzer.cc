// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

#include "zeek/Conn.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/plugin/Manager.h"
#include "zeek/session/Manager.h"

using namespace zeek;
using namespace zeek::packet_analysis::IP;

IPBasedAnalyzer::IPBasedAnalyzer(const char* name, TransportProto proto, uint32_t mask,
                                 bool report_unknown_protocols)
	: zeek::packet_analysis::Analyzer(name, report_unknown_protocols), transport(proto),
	  server_port_mask(mask)
	{
	}

IPBasedAnalyzer::~IPBasedAnalyzer()
	{
	for ( const auto& mapping : analyzers_by_port )
		delete mapping.second;
	}

bool IPBasedAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* pkt)
	{
	ConnTuple tuple;
	if ( ! BuildConnTuple(len, data, pkt, tuple) )
		return false;

	const std::shared_ptr<IP_Hdr>& ip_hdr = pkt->ip_hdr;
	detail::ConnKey key(tuple);

	Connection* conn = session_mgr->FindConnection(key);

	if ( ! conn )
		{
		conn = NewConn(&tuple, key, pkt);
		if ( conn )
			session_mgr->Insert(conn, false);
		}
	else
		{
		if ( conn->IsReuse(run_state::processing_start_time, ip_hdr->Payload()) )
			{
			conn->Event(connection_reused, nullptr);

			session_mgr->Remove(conn);
			conn = NewConn(&tuple, key, pkt);
			if ( conn )
				session_mgr->Insert(conn, false);
			}
		else
			{
			conn->CheckEncapsulation(pkt->encap);
			}
		}

	if ( ! conn )
		return false;

	// If we successfully made a connection for this packet that means it'll eventually
	// get logged, which means we can mark this packet as having been processed.
	pkt->processed = true;

	bool is_orig = (tuple.src_addr == conn->OrigAddr()) && (tuple.src_port == conn->OrigPort());
	pkt->is_orig = is_orig;

	conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

	zeek::ValPtr pkt_hdr_val;

	if ( ipv6_ext_headers && ip_hdr->NumHeaders() > 1 )
		{
		pkt_hdr_val = ip_hdr->ToPktHdrVal();
		conn->EnqueueEvent(ipv6_ext_headers, nullptr, conn->GetVal(), pkt_hdr_val);
		}

	if ( new_packet )
		conn->EnqueueEvent(new_packet, nullptr, conn->GetVal(),
		                   pkt_hdr_val ? std::move(pkt_hdr_val) : ip_hdr->ToPktHdrVal());

	conn->SetRecordPackets(true);
	conn->SetRecordContents(true);

	const u_char* payload = pkt->ip_hdr->Payload();

	run_state::current_timestamp = run_state::processing_start_time;
	run_state::current_pkt = pkt;

	// TODO: Does this actually mean anything?
	if ( conn->GetSessionAdapter()->Skipping() )
		return true;

	DeliverPacket(conn, run_state::processing_start_time, is_orig, len, pkt);

	run_state::current_timestamp = 0;
	run_state::current_pkt = nullptr;

	// If the packet is reassembled, disable packet dumping because the
	// pointer math to dump the data wouldn't work.
	if ( pkt->ip_hdr->Reassembled() )
		pkt->dump_packet = false;
	else if ( conn->RecordPackets() )
		{
		pkt->dump_packet = true;

		// If we don't want the content, set the dump size to include just
		// the header.
		if ( ! conn->RecordContents() )
			pkt->dump_size = payload - pkt->data;
		}

	return true;
	}

bool IPBasedAnalyzer::CheckHeaderTrunc(size_t min_hdr_len, size_t remaining, Packet* packet)
	{
	// If segment offloading or similar is enabled, the payload len will return 0.
	// Thus, let's ignore that case.
	if ( packet->ip_hdr->PayloadLen() && packet->ip_hdr->PayloadLen() < min_hdr_len )
		{
		Weird("truncated_header", packet);
		return false;
		}
	else if ( remaining < min_hdr_len )
		{
		Weird("internally_truncated_header", packet);
		return false;
		}

	return true;
	}

bool IPBasedAnalyzer::IsLikelyServerPort(uint32_t port) const
	{
	// We keep a cached in-core version of the table to speed up the lookup.
	static std::set<zeek_uint_t> port_cache;
	static bool have_cache = false;

	if ( ! have_cache )
		{
		auto likely_server_ports = id::find_val<TableVal>("likely_server_ports");
		auto lv = likely_server_ports->ToPureListVal();
		for ( int i = 0; i < lv->Length(); i++ )
			port_cache.insert(lv->Idx(i)->InternalUnsigned());
		have_cache = true;
		}

	// We exploit our knowledge of PortVal's internal storage mechanism here.
	port |= server_port_mask;

	return port_cache.find(port) != port_cache.end();
	}

zeek::Connection* IPBasedAnalyzer::NewConn(const ConnTuple* id, const detail::ConnKey& key,
                                           const Packet* pkt)
	{
	int src_h = ntohs(id->src_port);
	int dst_h = ntohs(id->dst_port);
	bool flip = false;

	if ( ! WantConnection(src_h, dst_h, pkt->ip_hdr->Payload(), flip) )
		return nullptr;

	Connection* conn = new Connection(key, run_state::processing_start_time, id,
	                                  pkt->ip_hdr->FlowLabel(), pkt);
	conn->SetTransport(transport);

	if ( flip )
		conn->FlipRoles();

	BuildSessionAnalyzerTree(conn);

	if ( new_connection )
		conn->Event(new_connection, nullptr);

	return conn;
	}

void IPBasedAnalyzer::BuildSessionAnalyzerTree(Connection* conn)
	{
	SessionAdapter* root = MakeSessionAdapter(conn);
	analyzer::pia::PIA* pia = MakePIA(conn);

	bool scheduled = analyzer_mgr->ApplyScheduledAnalyzers(conn, false, root);

	// Hmm... Do we want *just* the expected analyzer, or all
	// other potential analyzers as well?  For now we only take
	// the scheduled ones.
	if ( ! scheduled )
		{ // Let's see if it's a port we know.
		if ( ! analyzers_by_port.empty() && ! zeek::detail::dpd_ignore_ports )
			{
			int resp_port = ntohs(conn->RespPort());
			std::set<zeek::Tag>* ports = LookupPort(resp_port, false);

			if ( ports )
				{
				for ( const auto& port : *ports )
					{
					analyzer::Analyzer* analyzer = analyzer_mgr->InstantiateAnalyzer(port, conn);

					if ( ! analyzer )
						continue;

					root->AddChildAnalyzer(analyzer, false);
					DBG_ANALYZER_ARGS(conn, "activated %s analyzer due to port %d",
					                  analyzer_mgr->GetComponentName(port).c_str(), resp_port);
					}
				}
			}
		}

	root->AddExtraAnalyzers(conn);

	if ( pia )
		root->AddChildAnalyzer(pia->AsAnalyzer());

	conn->SetSessionAdapter(root, pia);
	root->Init();
	root->InitChildren();

	PLUGIN_HOOK_VOID(HOOK_SETUP_ANALYZER_TREE, HookSetupAnalyzerTree(conn));
	}

bool IPBasedAnalyzer::RegisterAnalyzerForPort(const zeek::Tag& tag, uint32_t port)
	{
	tag_set* l = LookupPort(port, true);

	if ( ! l )
		return false;

#ifdef DEBUG
	const char* name = analyzer_mgr->GetComponentName(tag).c_str();
	DBG_LOG(DBG_ANALYZER, "Registering analyzer %s for port %" PRIu32 "/%d", name, port, transport);
#endif

	l->insert(tag);
	return true;
	}

bool IPBasedAnalyzer::UnregisterAnalyzerForPort(const zeek::Tag& tag, uint32_t port)
	{
	tag_set* l = LookupPort(port, true);

	if ( ! l )
		return true; // still a "successful" unregistration

#ifdef DEBUG
	const char* name = analyzer_mgr->GetComponentName(tag).c_str();
	DBG_LOG(DBG_ANALYZER, "Unregistering analyzer %s for port %" PRIu32 "/%d", name, port,
	        transport);
#endif

	l->erase(tag);
	return true;
	}

IPBasedAnalyzer::tag_set* IPBasedAnalyzer::LookupPort(uint32_t port, bool add_if_not_found)
	{
	analyzer_map_by_port::const_iterator i = analyzers_by_port.find(port);

	if ( i != analyzers_by_port.end() )
		return i->second;

	if ( ! add_if_not_found )
		return nullptr;

	tag_set* l = new tag_set{};
	analyzers_by_port.insert(std::make_pair(port, l));
	return l;
	}

void IPBasedAnalyzer::DumpPortDebug()
	{
	for ( const auto& mapping : analyzers_by_port )
		{
		std::string s;

		for ( const auto& tag : *(mapping.second) )
			s += std::string(analyzer_mgr->GetComponentName(tag)) + " ";

		DBG_LOG(DBG_ANALYZER, "    %d/%s: %s", mapping.first, transport_proto_string(transport),
		        s.c_str());
		}
	}

TableValPtr IPBasedAnalyzer::ignore_checksums_nets_table = nullptr;

void IPBasedAnalyzer::SetIgnoreChecksumsNets(TableValPtr t)
	{
	IPBasedAnalyzer::ignore_checksums_nets_table = t;
	}

TableValPtr IPBasedAnalyzer::GetIgnoreChecksumsNets()
	{
	if ( ! IPBasedAnalyzer::ignore_checksums_nets_table )
		IPBasedAnalyzer::ignore_checksums_nets_table = zeek::id::find_val<TableVal>(
			"ignore_checksums_nets");
	return IPBasedAnalyzer::ignore_checksums_nets_table;
	}
