// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/Manager.h"

#include "zeek/RunState.h"
#include "zeek/Stats.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktDumper.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Dispatcher.h"
#include "zeek/plugin/Manager.h"
#include "zeek/zeek-bif.h"

using namespace zeek::packet_analysis;

Manager::Manager()
	: plugin::ComponentManager<packet_analysis::Component>("PacketAnalyzer", "Tag", "AllAnalyzers")
	{
	}

Manager::~Manager()
	{
	delete pkt_profiler;
	delete pkt_filter;
	}

void Manager::InitPostScript(const std::string& unprocessed_output_file)
	{
	// Instantiate objects for all available analyzers
	for ( const auto& analyzerComponent : GetComponents() )
		{
		if ( AnalyzerPtr newAnalyzer = InstantiateAnalyzer(analyzerComponent->Tag()) )
			{
			newAnalyzer->SetEnabled(analyzerComponent->Enabled());
			analyzers.emplace(analyzerComponent->Name(), newAnalyzer);
			}
		}

	// Initialize all analyzers
	for ( auto& [name, analyzer] : analyzers )
		analyzer->Initialize();

	root_analyzer = analyzers["Root"];

	auto pkt_profile_file = id::find_val("pkt_profile_file");

	if ( detail::pkt_profile_mode && detail::pkt_profile_freq > 0 && pkt_profile_file )
		pkt_profiler = new detail::PacketProfiler(
			detail::pkt_profile_mode, detail::pkt_profile_freq, pkt_profile_file->AsFile());

	unknown_sampling_rate = id::find_val("UnknownProtocol::sampling_rate")->AsCount();
	unknown_sampling_threshold = id::find_val("UnknownProtocol::sampling_threshold")->AsCount();
	unknown_sampling_duration = id::find_val("UnknownProtocol::sampling_duration")->AsInterval();
	unknown_first_bytes_count = id::find_val("UnknownProtocol::first_bytes_count")->AsCount();

	if ( ! unprocessed_output_file.empty() )
		// This gets automatically cleaned up by iosource_mgr. No need to delete it locally.
		unprocessed_dumper = iosource_mgr->OpenPktDumper(unprocessed_output_file, true);
	}

void Manager::Done() { }

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

AnalyzerPtr Manager::GetAnalyzer(EnumVal* val)
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

bool Manager::EnableAnalyzer(EnumVal* tag)
	{
	Component* c = Lookup(tag);
	c->SetEnabled(true);

	return true;
	}

bool Manager::DisableAnalyzer(EnumVal* tag)
	{
	Component* c = Lookup(tag);
	c->SetEnabled(false);

	return true;
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
		DumpPacket(packet, packet->dump_size);
		dumped_packet = true;
		}

	// Start packet analysis
	root_analyzer->ForwardPacket(packet->cap_len, packet->data, packet, packet->link_type);

	if ( ! packet->processed )
		{
		if ( packet_not_processed )
			event_mgr.Enqueue(packet_not_processed, Packet::ToVal(packet));

		plugin_mgr->HookUnprocessedPacket(packet);

		if ( unprocessed_dumper )
			unprocessed_dumper->Dump(packet);

		total_not_processed++;
		}

	if ( raw_packet )
		event_mgr.Enqueue(raw_packet, packet->ToRawPktHdrVal());

	// Check whether packet should be recorded based on session analysis
	if ( packet->dump_packet && ! dumped_packet )
		DumpPacket(packet, packet->dump_size);
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
		reporter->InternalWarning("analyzer %s cannot be instantiated dynamically",
		                          GetComponentName(tag).c_str());
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
		reporter->InternalError("Mismatch of requested analyzer %s and instantiated analyzer %s. "
		                        "This usually means that the plugin author made a mistake.",
		                        GetComponentName(tag).c_str(),
		                        GetComponentName(a->GetAnalyzerTag()).c_str());
		}

	return a;
	}

AnalyzerPtr Manager::InstantiateAnalyzer(const std::string& name)
	{
	Tag tag = GetComponentTag(name);
	return tag ? InstantiateAnalyzer(tag) : nullptr;
	}

void Manager::DumpPacket(const Packet* pkt, int len)
	{
	if ( ! run_state::detail::pkt_dumper )
		return;

	if ( len != 0 )
		{
		if ( (uint32_t)len > pkt->cap_len )
			reporter->Warning("bad modified caplen");
		else
			const_cast<Packet*>(pkt)->cap_len = len;
		}

	run_state::detail::pkt_dumper->Dump(pkt);
	}

class UnknownProtocolTimer final : public zeek::detail::Timer
	{
public:
	// Represents a combination of an analyzer name and protocol identifier, where the identifier
	// was reported as unknown by the analyzer.
	using UnknownProtocolPair = std::pair<std::string, uint32_t>;

	UnknownProtocolTimer(double t, UnknownProtocolPair p, double timeout)
		: zeek::detail::Timer(t + timeout, zeek::detail::TIMER_UNKNOWN_PROTOCOL_EXPIRE),
		  unknown_protocol(std::move(p))
		{
		}

	void Dispatch(double t, bool is_expire) override
		{
		zeek::packet_mgr->ResetUnknownProtocolTimer(unknown_protocol.first,
		                                            unknown_protocol.second);
		}

	UnknownProtocolPair unknown_protocol;
	};

void Manager::ResetUnknownProtocolTimer(const std::string& analyzer, uint32_t protocol)
	{
	unknown_protocols.erase(std::make_pair(analyzer, protocol));
	}

bool Manager::PermitUnknownProtocol(const std::string& analyzer, uint32_t protocol)
	{
	auto p = std::make_pair(analyzer, protocol);
	uint64_t& count = unknown_protocols[p];
	++count;

	if ( count == 1 )
		detail::timer_mgr->Add(
			new UnknownProtocolTimer(run_state::network_time, p, unknown_sampling_duration));

	if ( count < unknown_sampling_threshold )
		return true;

	auto num_above_threshold = count - unknown_sampling_threshold;
	if ( unknown_sampling_rate )
		return num_above_threshold % unknown_sampling_rate == 0;

	return false;
	}

void Manager::ReportUnknownProtocol(const std::string& analyzer, uint32_t protocol,
                                    const uint8_t* data, size_t len)
	{
	if ( unknown_protocol )
		{
		if ( PermitUnknownProtocol(analyzer, protocol) )
			{
			int bytes_len = std::min(unknown_first_bytes_count, static_cast<uint64_t>(len));

			event_mgr.Enqueue(unknown_protocol, make_intrusive<StringVal>(analyzer),
			                  val_mgr->Count(protocol),
			                  make_intrusive<StringVal>(bytes_len, (const char*)data));
			}
		}
	}
