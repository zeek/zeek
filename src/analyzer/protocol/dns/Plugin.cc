// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "DNS.h"

namespace plugin {
namespace Bro_DNS {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("DNS", ::analyzer::dns::DNS_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Contents_DNS", 0));

		plugin::Configuration config;
		config.name = "Bro::DNS";
		config.description = "DNS analyzer";
		return config;
		}
} plugin;

}
}
