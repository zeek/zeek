// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "ICMP.h"

namespace plugin {
namespace Zeek_ICMP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("ICMP", ::analyzer::icmp::ICMP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::ICMP";
		config.description = "ICMP analyzer";
		return config;
		}
} plugin;

}
}
