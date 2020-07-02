#include "RFB.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_RFB {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("RFB",
		             ::analyzer::rfb::RFB_Analyzer::InstantiateAnalyzer));

		zeek::plugin::Configuration config;
		config.name = "Zeek::RFB";
		config.description = "Parser for rfb (VNC) analyzer";
		return config;
		}
} plugin;

}
}
