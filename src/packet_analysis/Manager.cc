// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include <list>
#include <pcap.h>

#include "Config.h"
#include "NetVar.h"
#include "plugin/Manager.h"
#include "Analyzer.h"
#include "Dispatcher.h"

using namespace zeek::packet_analysis;

Manager::Manager()
	: plugin::ComponentManager<packet_analysis::Tag, packet_analysis::Component>("PacketAnalyzer", "Tag")
	{
	}

Manager::~Manager()
	{
	}

void Manager::InitPostScript()
	{
	auto analyzer_mapping = zeek::id::find("PacketAnalyzer::config_map");
	if ( ! analyzer_mapping )
		return;

	auto mapping_val = analyzer_mapping->GetVal()->AsVectorVal();
	if ( mapping_val->Size() == 0 )
		return;

	Config configuration;
	for (unsigned int i = 0; i < mapping_val->Size(); i++)
		{
		auto* rv = mapping_val->At(i)->AsRecordVal();
		auto parent = rv->GetField("parent");
		std::string parent_name = parent ? Lookup(parent->AsEnumVal())->Name() : "ROOT";
		auto identifier = rv->GetField("identifier")->AsCount();
		auto analyzer = rv->GetField("analyzer")->AsEnumVal();

		configuration.AddMapping(parent_name, identifier, Lookup(analyzer)->Name());
		}

	// Instantiate objects for all analyzers
	for ( const auto& current_dispatcher_config : configuration.GetDispatchers() )
		{
		for ( const auto& current_mapping : current_dispatcher_config.GetMappings() )
			{
			// Check if already instantiated
			if ( analyzers.count(current_mapping.second) != 0 )
				continue;

			// Check if analyzer exists
			if ( AnalyzerPtr newAnalyzer = InstantiateAnalyzer(current_mapping.second) )
				analyzers.emplace(current_mapping.second, newAnalyzer);
			}
		}

	// Generate Dispatchers, starting at root
	root_dispatcher = GetDispatcher(configuration, "ROOT");
	if ( root_dispatcher == nullptr )
		reporter->InternalError("No dispatching configuration for ROOT of packet_analysis set.");

	// Set up default analysis
	auto it = analyzers.find("DefaultAnalyzer");
	if ( it != analyzers.end() )
		default_analyzer = it->second;
	else
		default_analyzer = InstantiateAnalyzer("DefaultAnalyzer");

	default_dispatcher = nullptr;
	if ( default_analyzer != nullptr )
		default_dispatcher = GetDispatcher(configuration, "DefaultAnalyzer");

	current_state = root_dispatcher;
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

	DBG_LOG(DBG_PACKET_ANALYSIS, "ProtocolAnalyzerSet FSM:");
	for ( const auto& current : dispatchers )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "  Dispatcher (%p): %s", current.second.get(), current.first.c_str());
		current.second->DumpDebug();
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
		return nullptr;
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

	// Dispatch and analyze layers
	AnalyzerResult result = AnalyzerResult::Continue;
	uint32_t next_layer_id = packet->link_type;
	const uint8_t* data = packet->data;
	do
		{
		auto current_analyzer = Dispatch(next_layer_id);

		// Analyzer not found
		if ( current_analyzer == nullptr )
			{
			DBG_LOG(DBG_PACKET_ANALYSIS, "Could not find analyzer for identifier %#x", next_layer_id);
			packet->Weird("no_suitable_analyzer_found");
			break;
			}

		// Analyze this layer and get identifier of next layer protocol
		std::tie(result, next_layer_id) = current_analyzer->Analyze(packet, data);

#ifdef DEBUG
		switch ( result )
			{
			case AnalyzerResult::Continue:
				DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#x.",
				        current_analyzer->GetAnalyzerName(), next_layer_id);
				break;
			case AnalyzerResult::Terminate:
				DBG_LOG(DBG_PACKET_ANALYSIS, "Done, last found layer identifier was %#x.", next_layer_id);
				break;
			case AnalyzerResult::Failed:
				DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis failed in %s", current_analyzer->GetAnalyzerName());
			}
#endif

		} while ( result == AnalyzerResult::Continue );

	if ( result == AnalyzerResult::Terminate )
		CustomEncapsulationSkip(packet, data);

	// Processing finished, reset analyzer set state for next packet
	current_state = root_dispatcher;

	// Calculate header size after processing packet layers.
	packet->hdr_size = data - packet->data;
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

AnalyzerPtr Manager::Dispatch(uint32_t identifier)
	{
	// Because leaf nodes (aka no more dispatching) can still have an existing analyzer that returns more identifiers,
	// current_state needs to be checked to be not null. In this case there would have been an analyzer dispatched
	// in the last layer, but no dispatcher for it (end of FSM)
	ValuePtr result = nullptr;
	if ( current_state )
		result = current_state->Lookup(identifier);

	if ( result == nullptr )
		{
		if ( current_state != default_dispatcher )
			{
			// Switch to default analysis once
			current_state = default_dispatcher;
			return default_analyzer;
			}
		return nullptr;
		}
	else
		{
		current_state = result->dispatcher;
		return result->analyzer;
		}
	}

DispatcherPtr Manager::GetDispatcher(Config& configuration, const std::string& dispatcher_name)
	{
	// Is it already created?
	if ( dispatchers.count(dispatcher_name) != 0 )
		return dispatchers[dispatcher_name];

	// Create new dispatcher from config
	std::optional<std::reference_wrapper<DispatcherConfig>> dispatcher_config =
		configuration.GetDispatcherConfig(dispatcher_name);

	if ( ! dispatcher_config )
		// No such dispatcher found, this is therefore implicitly a leaf
		return nullptr;

	const auto& mappings = dispatcher_config->get().GetMappings();

	DispatcherPtr dispatcher = std::make_shared<Dispatcher>();
	dispatchers.emplace(dispatcher_name, dispatcher);

	for ( const auto& current_mapping : mappings )
		{
		// No analyzer with this name. Report warning and ignore.
		if ( analyzers.count(current_mapping.second) == 0 )
			{
			reporter->InternalWarning("No analyzer %s found for dispatching identifier %#x of %s, ignoring.",
			                          current_mapping.second.c_str(),
			                          current_mapping.first,
			                          dispatcher_name.c_str());
			continue;
			}

		dispatcher->Register(current_mapping.first, analyzers.at(current_mapping.second),
		                     GetDispatcher(configuration, current_mapping.second));
		}

	return dispatcher;
	}
