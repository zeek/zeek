// See the file "COPYING" in the main distribution directory for copyright.

#include <list>
#include <pcap.h>

#include "Config.h"
#include "Manager.h"
#include "NetVar.h"
#include "ProtocolAnalyzerSet.h"
#include "plugin/Manager.h"

using namespace zeek::packet_analysis;

Manager::Manager()
	: plugin::ComponentManager<packet_analysis::Tag, packet_analysis::Component>("PacketAnalyzer", "Tag")
	{
	}

Manager::~Manager()
	{
	delete analyzer_set;
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

	analyzer_set = new ProtocolAnalyzerSet(configuration, "DefaultAnalyzer");
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
		DBG_LOG(DBG_PACKET_ANALYSIS, "    %s (%s)", current->Name().c_str(), IsEnabled(current->Tag()) ? "enabled" : "disabled");
		}

	// Dump Analyzer Set
	if (analyzer_set)
		analyzer_set->DumpDebug();
#endif
	}

bool Manager::EnableAnalyzer(const Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	DBG_LOG(DBG_PACKET_ANALYSIS, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::EnableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	DBG_LOG(DBG_PACKET_ANALYSIS, "Enabling analyzer %s", p->Name().c_str());
	p->SetEnabled(true);

	return true;
	}

bool Manager::DisableAnalyzer(const Tag& tag)
	{
	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	DBG_LOG(DBG_PACKET_ANALYSIS, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

bool Manager::DisableAnalyzer(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	DBG_LOG(DBG_PACKET_ANALYSIS, "Disabling analyzer %s", p->Name().c_str());
	p->SetEnabled(false);

	return true;
	}

void Manager::DisableAllAnalyzers()
	{
	DBG_LOG(DBG_PACKET_ANALYSIS, "Disabling all analyzers");

	std::list<Component*> all_analyzers = GetComponents();
	for ( const auto& analyzer : all_analyzers )
		analyzer->SetEnabled(false);
	}

zeek::packet_analysis::Tag Manager::GetAnalyzerTag(const char* name)
	{
	return GetComponentTag(name);
	}

bool Manager::IsEnabled(Tag tag)
	{
	if ( ! tag )
		return false;

	Component* p = Lookup(tag);

	if ( ! p )
		return false;

	return p->Enabled();
	}

bool Manager::IsEnabled(EnumVal* val)
	{
	Component* p = Lookup(val);

	if ( ! p )
		return false;

	return p->Enabled();
	}

Analyzer* Manager::InstantiateAnalyzer(const Tag& tag)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->InternalWarning("request to instantiate unknown packet_analysis");
		return nullptr;
		}

	if ( ! c->Enabled() )
		return nullptr;

	if ( ! c->Factory() )
		{
		reporter->InternalWarning("analyzer %s cannot be instantiated dynamically", GetComponentName(tag).c_str());
		return nullptr;
		}

	Analyzer* a = c->Factory()();

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

Analyzer* Manager::InstantiateAnalyzer(const std::string& name)
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

	if ( ! analyzer_set )
		return;

	// Dispatch and analyze layers
	AnalyzerResult result = AnalyzerResult::Continue;
	identifier_t next_layer_id = packet->link_type;
	do
		{
		auto current_analyzer = analyzer_set->Dispatch(next_layer_id);

		// Analyzer not found
		if ( current_analyzer == nullptr )
			{
			DBG_LOG(DBG_PACKET_ANALYSIS, "Could not find analyzer for identifier %#x", next_layer_id);
			packet->Weird("no_suitable_analyzer_found");
			break;
			}

		// Analyze this layer and get identifier of next layer protocol
		std::tie(result, next_layer_id) = current_analyzer->Analyze(packet);

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
		CustomEncapsulationSkip(packet);

	// Processing finished, reset analyzer set state for next packet
	analyzer_set->Reset();
	}

void Manager::CustomEncapsulationSkip(Packet* packet)
	{
	if ( zeek::detail::encap_hdr_size > 0 )
		{
		auto pdata = packet->cur_pos;

		// Blanket encapsulation. We assume that what remains is IP.
		if ( pdata + zeek::detail::encap_hdr_size + sizeof(struct ip) >= packet->GetEndOfData() )
			{
			packet->Weird("no_ip_left_after_encap");
			return;
			}

		pdata += zeek::detail::encap_hdr_size;

		auto ip = (const struct ip*)pdata;

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
