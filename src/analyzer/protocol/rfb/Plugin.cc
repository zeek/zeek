#include "RFB.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_RFB {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("RFB",
		             ::analyzer::rfb::RFB_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Zeek::RFB";
		config.description = "Parser for rfb (VNC) analyzer";
		return config;
		}
} plugin;

}
}
