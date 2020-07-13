// See the file "COPYING" in the main distribution directory for copyright.

#include "Default.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_Default {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("DefaultAnalyzer",
		                 zeek::packet_analysis::Default::DefaultAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::DefaultAnalyzer";
		config.description = "Default packet analyzer for IP fallback";
		return config;
		}

} plugin;

}
