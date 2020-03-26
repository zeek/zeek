// See the file  in the main distribution directory for copyright.

#include "SNMP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_SNMP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("SNMP", ::analyzer::snmp::SNMP_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Zeek::SNMP";
		config.description = "SNMP analyzer";
		return config;
		}
} plugin;

}
}
