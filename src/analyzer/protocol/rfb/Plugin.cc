#include "plugin/Plugin.h"

#include "RFB.h"

namespace plugin {
namespace Bro_RFB {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("RFB",
		             ::analyzer::rfb::RFB_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Bro::RFB";
		config.description = "Parser for rfb (VNC) analyzer";
		return config;
		}
} plugin;

}
}