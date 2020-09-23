// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "LinuxSLL.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_LinuxSLL {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("LinuxSLL",
		                 zeek::packet_analysis::LinuxSLL::LinuxSLLAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::LinuxSLL";
		config.description = "Linux cooked capture (SLL) packet analyzer";
		return config;
		}

} plugin;

}
