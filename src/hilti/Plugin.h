

#ifndef HILTI_PAC2_PLUGIN_H
#define HILTI_PAC2_PLUGIN_H

#include "plugin/Plugin.h"
#include "analyzer/Tag.h"

#include "../net_util.h"

namespace bro {
namespace hilti {

struct Pac2AnalyzerInfo;

class Plugin : public plugin::Plugin {
public:
	analyzer::Tag AddAnalyzer(const std::string& name, TransportProto proto, analyzer::Tag::subtype_t stype);
	void AddEvent(const std::string& name);

	void Init() override;

protected:
	bif_item_list CustomBifItems() override;

private:
	plugin::Plugin::component_list components;
	bif_item_list custom_bif_items;
};

}
}

#endif
