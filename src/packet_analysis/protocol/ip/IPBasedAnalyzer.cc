// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

#include "zeek/RunState.h"
#include "zeek/Conn.h"
#include "zeek/Val.h"
#include "zeek/session/Manager.h"
#include "zeek/analyzer/Manager.h"

using namespace zeek;
using namespace zeek::packet_analysis::IP;

IPBasedAnalyzer::IPBasedAnalyzer(const char* name, TransportProto proto, uint32_t mask,
                                 bool report_unknown_protocols)
	: zeek::packet_analysis::Analyzer(name, report_unknown_protocols),
	  transport(proto), server_port_mask(mask)
	{
	}

IPBasedAnalyzer::~IPBasedAnalyzer()
	{
	}

bool IPBasedAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* pkt)
	{
	ConnTuple tuple;
	if ( ! BuildConnTuple(len, data, pkt, tuple) )
		return false;

	const std::unique_ptr<IP_Hdr>& ip_hdr = pkt->ip_hdr;
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

	bool is_orig = (tuple.src_addr == conn->OrigAddr()) &&
	               (tuple.src_port == conn->OrigPort());

	conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

	zeek::ValPtr pkt_hdr_val;

	if ( ipv6_ext_headers && ip_hdr->NumHeaders() > 1 )
		{
		pkt_hdr_val = ip_hdr->ToPktHdrVal();
		conn->EnqueueEvent(ipv6_ext_headers, nullptr, conn->GetVal(),
		                   pkt_hdr_val);
		}

	if ( new_packet )
		conn->EnqueueEvent(new_packet, nullptr, conn->GetVal(),
		                   pkt_hdr_val ? std::move(pkt_hdr_val) : ip_hdr->ToPktHdrVal());

	if ( new_plugin )
		{
		conn->SetRecordPackets(true);
		conn->SetRecordContents(true);

		const u_char* data = pkt->ip_hdr->Payload();

		run_state::current_timestamp = run_state::processing_start_time;
		run_state::current_pkt = pkt;

		// TODO: Does this actually mean anything?
		if ( conn->Skipping() )
			return true;

		DeliverPacket(conn, run_state::processing_start_time, is_orig, len, pkt);

		run_state::current_timestamp = 0;
		run_state::current_pkt = nullptr;

		// If the packet is reassembled, disable packet dumping because the
		// pointer math to dump the data wouldn't work.
		if ( pkt->ip_hdr->reassembled )
			pkt->dump_packet = false;
		else if ( conn->RecordPackets() )
			{
			pkt->dump_packet = true;

			// If we don't want the content, set the dump size to include just
			// the header.
			if ( ! conn->RecordContents() )
				pkt->dump_size = data - pkt->data;
			}
		}
	else
		{
		int record_packet = 1;	// whether to record the packet at all
		int record_content = 1;	// whether to record its data

		const u_char* data = pkt->ip_hdr->Payload();

		conn->NextPacket(run_state::processing_start_time, is_orig, ip_hdr.get(), ip_hdr->PayloadLen(),
		                 len, data, record_packet, record_content, pkt);

		// If the packet is reassembled, disable packet dumping because the
		// pointer math to dump the data wouldn't work.
		if ( ip_hdr->reassembled )
			pkt->dump_packet = false;
		else if ( record_packet )
			{
			pkt->dump_packet = true;

			// If we don't want the content, set the dump size to include just
			// the header.
			if ( ! record_content )
				pkt->dump_size = data - pkt->data;
			}
		}

	return true;
	}

bool IPBasedAnalyzer::CheckHeaderTrunc(size_t min_hdr_len, size_t remaining, Packet* packet)
	{
	if ( packet->ip_hdr->PayloadLen() < min_hdr_len )
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
	static std::set<bro_uint_t> port_cache;
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

	Connection* conn = new Connection(key, run_state::processing_start_time,
	                                  id, pkt->ip_hdr->FlowLabel(), pkt);
	conn->SetTransport(transport);

	if ( flip )
		conn->FlipRoles();

	if ( ! new_plugin )
		{
		if ( ! analyzer_mgr->BuildInitialAnalyzerTree(conn) )
			{
			conn->Done();
			Unref(conn);
			return nullptr;
			}
		}
	else if ( ! analyzer_mgr->BuildSessionAnalyzerTree(conn, this) )
		{
		conn->Done();
		Unref(conn);
		return nullptr;
		}

	if ( new_connection )
		conn->Event(new_connection, nullptr);

	return conn;
	}
