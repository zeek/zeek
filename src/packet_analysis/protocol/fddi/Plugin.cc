// See the file "COPYING" in the main distribution directory for copyright.

#include "FDDI.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_FDDI {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("FDDI",
		                 zeek::packet_analysis::FDDI::FDDIAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FDDI";
		config.description = "FDDI packet analyzer";
		return config;
		}

} plugin;

}
