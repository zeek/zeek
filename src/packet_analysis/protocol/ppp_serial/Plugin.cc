// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPSerial.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_PPPSerial {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("PPPSerial",
		                 zeek::packet_analysis::PPPSerial::PPPSerialAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::PPPSerial";
		config.description = "PPPSerial packet analyzer";
		return config;
		}

} plugin;

}
