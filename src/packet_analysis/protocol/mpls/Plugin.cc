// See the file "COPYING" in the main distribution directory for copyright.

#include "MPLS.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_MPLS {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("MPLS",
		                 zeek::packet_analysis::MPLS::MPLSAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::MPLS";
		config.description = "MPLS packet analyzer";
		return config;
		}

} plugin;

}
