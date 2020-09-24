// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include "Analyzer.h"
#include "Dispatcher.h"
#include "zeek-bif.h"
#include "Stats.h"
#include "zeek/Sessions.h"
#include "zeek/RunState.h"
#include "iosource/PktDumper.h"

using namespace zeek::packet_analysis;

Manager::Manager()
	: plugin::ComponentManager<packet_analysis::Tag, packet_analysis::Component>("PacketAnalyzer", "Tag")
	{
	}

Manager::~Manager()
	{
	delete pkt_profiler;
	}

void Manager::InitPostScript()
	{
	// Instantiate objects for all available analyzers
	for ( const auto& analyzerComponent : GetComponents() )
		{
		if ( AnalyzerPtr newAnalyzer = InstantiateAnalyzer(analyzerComponent->Tag()) )
			analyzers.emplace(analyzerComponent->Name(), newAnalyzer);
		}

	// Initialize all analyzers
	for ( auto& [name, analyzer] : analyzers )
		analyzer->Initialize();

	root_analyzer = analyzers["Root"];

	static auto pkt_profile_file = id::find_val("pkt_profile_file");

	if ( detail::pkt_profile_mode && detail::pkt_profile_freq > 0 && pkt_profile_file )
		pkt_profiler = new detail::PacketProfiler(detail::pkt_profile_mode,
		                                          detail::pkt_profile_freq,
		                                          pkt_profile_file->AsFile());
	}

void Manager::Done()
	{
	}

void Manager::DumpDebug()
	{
#ifdef DEBUG
	DBG_LOG(DBG_PACKET_ANALYSIS, "Available packet analyzers after zeek_init():");
	for ( auto& current : GetComponents() )
		DBG_LOG(DBG_PACKET_ANALYSIS, "    %s", current->Name().c_str());

	DBG_LOG(DBG_PACKET_ANALYSIS, "Packet analyzer debug information:");
	for ( auto& [name, analyzer] : analyzers )
		analyzer->DumpDebug();
#endif
	}

AnalyzerPtr Manager::GetAnalyzer(EnumVal *val)
	{
	auto analyzer_comp = Lookup(val);
	if ( ! analyzer_comp )
		return nullptr;

	return GetAnalyzer(analyzer_comp->Name());
	}

AnalyzerPtr Manager::GetAnalyzer(const std::string& name)
	{
	auto analyzer_it = analyzers.find(name);
	if ( analyzer_it == analyzers.end() )
		return nullptr;

	return analyzer_it->second;
	}

void Manager::ProcessPacket(Packet* packet)
	{
#ifdef DEBUG
	static size_t counter = 0;
	DBG_LOG(DBG_PACKET_ANALYSIS, "Analyzing packet %ld, ts=%.3f...", ++counter, packet->time);
#endif

	zeek::detail::SegmentProfiler prof(detail::segment_logger, "dispatching-packet");
	if ( pkt_profiler )
		pkt_profiler->ProfilePkt(zeek::run_state::processing_start_time, packet->cap_len);

	++num_packets_processed;

	bool dumped_packet = false;
	if ( packet->dump_packet || zeek::detail::record_all_packets )
		{
		DumpPacket(packet);
		dumped_packet = true;
		}

	// Start packet analysis
	packet->l2_valid = root_analyzer->ForwardPacket(packet->cap_len, packet->data,
			packet, packet->link_type);

	if ( raw_packet )
		event_mgr.Enqueue(raw_packet, packet->ToRawPktHdrVal());

	// Check whether packet should be recorded based on session analysis
	if ( packet->dump_packet && ! dumped_packet )
		DumpPacket(packet);
	}

bool Manager::ProcessInnerPacket(Packet* packet)
	{
	return root_analyzer->ForwardPacket(packet->cap_len, packet->data, packet, packet->link_type);
	}

AnalyzerPtr Manager::InstantiateAnalyzer(const Tag& tag)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->InternalWarning("request to instantiate unknown packet_analysis");
		return nullptr;
		}

	if ( ! c->Factory() )
		{
		reporter->InternalWarning("analyzer %s cannot be instantiated dynamically", GetComponentName(tag).c_str());
		return nullptr;
		}

	AnalyzerPtr a = c->Factory()();

	if ( ! a )
		{
		reporter->InternalWarning("analyzer instantiation failed");
		return nullptr;
		}

	if ( tag != a->GetAnalyzerTag() )
		{
		reporter->InternalError("Mismatch of requested analyzer %s and instantiated analyzer %s. This usually means that the plugin author made a mistake.",
								GetComponentName(tag).c_str(), GetComponentName(a->GetAnalyzerTag()).c_str());
		}

	return a;
	}

AnalyzerPtr Manager::InstantiateAnalyzer(const std::string& name)
	{
	Tag tag = GetComponentTag(name);
	return tag ? InstantiateAnalyzer(tag) : nullptr;
	}

void Manager::DumpPacket(const Packet *pkt, int len)
	{
	if ( ! run_state::detail::pkt_dumper )
		return;

	if ( len != 0 )
		{
		if ( (uint32_t)len > pkt->cap_len )
			reporter->Warning("bad modified caplen");
		else
			const_cast<Packet *>(pkt)->cap_len = len;
		}

	run_state::detail::pkt_dumper->Dump(pkt);
	}
