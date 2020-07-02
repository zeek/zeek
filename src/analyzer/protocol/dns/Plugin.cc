// See the file  in the main distribution directory for copyright.

#include "DNS.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_DNS {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("DNS", ::analyzer::dns::DNS_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Contents_DNS", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::DNS";
		config.description = "DNS analyzer";
		return config;
		}
} plugin;

}
}
