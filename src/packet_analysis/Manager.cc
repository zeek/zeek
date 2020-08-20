// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include "NetVar.h"
#include "Analyzer.h"
#include "Dispatcher.h"

using namespace zeek::packet_analysis;

Manager::Manager()
	: plugin::ComponentManager<packet_analysis::Tag, packet_analysis::Component>("PacketAnalyzer", "Tag")
	{
	}

void Manager::InitPostScript()
	{
	// Instantiate objects for all available analyzers
	for ( const auto& analyzerComponent : GetComponents() )
		{
		if ( AnalyzerPtr newAnalyzer = InstantiateAnalyzer(analyzerComponent->Tag()) )
			analyzers.emplace(analyzerComponent->Name(), newAnalyzer);
		}

	// Read in analyzer map and create dispatchers
	auto& analyzer_mapping = zeek::id::find("PacketAnalyzer::config_map");
	if ( ! analyzer_mapping )
		return;

	auto mapping_val = analyzer_mapping->GetVal()->AsVectorVal();
	if ( mapping_val->Size() == 0 )
		return;

	for (unsigned int i = 0; i < mapping_val->Size(); i++)
		{
		auto* rv = mapping_val->At(i)->AsRecordVal();
		//TODO: Make that field a string for usability reasons
		//TODO: Check error handling when fields are omitted
		auto& parent_tag = rv->GetField("parent");
		std::string parent_name = parent_tag ? Lookup(parent_tag->AsEnumVal())->Name() : "ROOT";
		auto identifier = rv->GetField("identifier")->AsCount();
		auto analyzer_tag = rv->GetField("analyzer")->AsEnumVal();
		auto analyzer_name = Lookup(analyzer_tag)->Name();

		if ( analyzers.find(analyzer_name) == analyzers.end() )
			{
			reporter->InternalWarning("Mapped analyzer %s not found.", analyzer_name.c_str());
			continue;
			}

		if ( parent_name == "ROOT" )
			{
			root_dispatcher.Register(identifier, analyzers[analyzer_name]);
			continue;
			}

		if ( analyzers.find(parent_name) == analyzers.end() )
			{
			reporter->InternalWarning("Parent analyzer %s not found.", parent_name.c_str());
			continue;
			}

		auto& parent_analyzer = analyzers[parent_name];
		parent_analyzer->RegisterAnalyzerMapping(identifier, analyzers[analyzer_name]);
		}

	// Set default analyzer
	auto da_it = analyzers.find("DefaultAnalyzer");
	if ( da_it == analyzers.end() )
		reporter->InternalError("DefaultAnalyzer not found.");
	default_analyzer = da_it->second;

	// Initialize all analyzers
	for ( auto& [name, analyzer] : analyzers )
		analyzer->Initialize();
	}

void Manager::Done()
	{
	}

void Manager::DumpDebug()
	{
#ifdef DEBUG
	DBG_LOG(DBG_PACKET_ANALYSIS, "Available packet analyzers after zeek_init():");
	for ( auto& current : GetComponents() )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "    %s", current->Name().c_str());
		}
#endif
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

void Manager::ProcessPacket(Packet* packet)
	{
#ifdef DEBUG
	static size_t counter = 0;
	DBG_LOG(DBG_PACKET_ANALYSIS, "Analyzing packet %ld, ts=%.3f...", ++counter, packet->time);
#endif
	// Start packet analysis
	const uint8_t* data = packet->data;

	auto root_analyzer = root_dispatcher.Lookup(packet->link_type);
	auto analyzer = root_analyzer == nullptr ? default_analyzer : root_analyzer;

	auto result = analyzer->Analyze(packet, data);
	if (result == AnalyzerResult::Terminate)
		CustomEncapsulationSkip(packet, data);

	// Calculate header size after processing packet layers.
	packet->hdr_size = static_cast<uint32_t>(data - packet->data);
	}

void Manager::CustomEncapsulationSkip(Packet* packet, const uint8_t* data)
	{
	if ( zeek::detail::encap_hdr_size > 0 )
		{
		// Blanket encapsulation. We assume that what remains is IP.
		if ( data + zeek::detail::encap_hdr_size + sizeof(struct ip) >= packet->GetEndOfData() )
			{
			packet->Weird("no_ip_left_after_encap");
			return;
			}

		data += zeek::detail::encap_hdr_size;

		auto ip = (const struct ip*)data;

		switch ( ip->ip_v )
			{
			case 4:
				packet->l3_proto = L3_IPV4;
				break;
			case 6:
				packet->l3_proto = L3_IPV6;
				break;
			default:
				{
				// Neither IPv4 nor IPv6.
				packet->Weird("no_ip_in_encap");
				return;
				}
			}
		}
	}
