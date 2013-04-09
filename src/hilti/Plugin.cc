
#include "Plugin.h"
#include "Pac2Analyzer.h"
#include "Loader.h"
#include "LocalReporter.h"
#include "analyzer/Component.h"

analyzer::Tag bro::hilti::Plugin::AddAnalyzer(const string& name, TransportProto proto, analyzer::Tag::subtype_t stype)
	{
	analyzer::Component::factory_callback factory = 0;

	switch ( proto ) {
	case TRANSPORT_TCP:
		factory = Pac2_TCP_Analyzer::InstantiateAnalyzer;
		break;

	case TRANSPORT_UDP:
		factory = Pac2_UDP_Analyzer::InstantiateAnalyzer;
		break;

	default:
		reporter::error("unsupported protocol in analyzer");
		return analyzer::Tag();
	}

	auto c = new analyzer::Component(name.c_str(), factory, stype);
	components.push_back(c);

	auto t = c->Tag();
	return t;
	}

void bro::hilti::Plugin::AddEvent(const string& name)
	{
	plugin::BifItem b(name, plugin::BifItem::EVENT);
	custom_bif_items.push_back(b);
	}

plugin::Plugin::bif_item_list bro::hilti::Plugin::CustomBifItems()
	{
	return custom_bif_items;
	}

void bro::hilti::Plugin::Init()
	{
	SetName("BinPAC++ Analyzers");
	SetDescription("Dynamically compiled BinPAC++ analyzers");

	for ( auto c : components )
		AddComponent(c);

	components.clear();
	}
