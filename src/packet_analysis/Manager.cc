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
		auto& parent_val = rv->GetField("parent");
		std::string parent_name = parent_val ? Lookup(parent_val->AsEnumVal())->Name() : "ROOT";
		auto& identifier_val = rv->GetField("identifier");
		auto analyzer_tag = rv->GetField("analyzer")->AsEnumVal();
		auto analyzer_name = Lookup(analyzer_tag)->Name();

		auto analyzer_it = analyzers.find(analyzer_name);
		if ( analyzer_it == analyzers.end() )
			{
			reporter->InternalWarning("Mapped analyzer %s not found.", analyzer_name.c_str());
			continue;
			}
		auto& analyzer = analyzer_it->second;

		if ( parent_name == "ROOT" )
			{
			if ( identifier_val )
				root_dispatcher.Register(identifier_val->AsCount(), analyzer);
			else
				default_analyzer = analyzer;
			continue;
			}

		auto parent_analyzer_it = analyzers.find(parent_name);
		if ( parent_analyzer_it == analyzers.end() )
			{
			reporter->InternalWarning("Parent analyzer %s not found.", parent_name.c_str());
			continue;
			}
		auto& parent_analyzer = parent_analyzer_it->second;

		if ( identifier_val )
			parent_analyzer->RegisterAnalyzerMapping(identifier_val->AsCount(), analyzer);
		else
			parent_analyzer->RegisterDefaultAnalyzer(analyzer);
		}

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

	DBG_LOG(DBG_PACKET_ANALYSIS, "Root dispatcher:");
	root_dispatcher.DumpDebug();
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
	// Start packet analysis
	const uint8_t* data = packet->data;

	auto root_analyzer = root_dispatcher.Lookup(packet->link_type);
	auto analyzer = root_analyzer ? root_analyzer : default_analyzer;
	if ( !analyzer )
		{
		reporter->InternalWarning("No analyzer for link type %#x", packet->link_type);
		return;
		}

	auto result = analyzer->Analyze(packet, data);
	if (result == AnalyzerResult::Terminate)
		CustomEncapsulationSkip(packet, data);

	// Calculate header size after processing packet layers.
	packet->hdr_size = static_cast<uint32_t>(data - packet->data);
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
