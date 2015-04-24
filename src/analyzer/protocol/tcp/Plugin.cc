// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "TCP.h"

namespace plugin {
namespace Bro_TCP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("TCP", ::analyzer::tcp::TCP_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("TCPStats", ::analyzer::tcp::TCPStats_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("CONTENTLINE", 0));
		AddComponent(new ::analyzer::Component("Contents", 0));

		plugin::Configuration config;
		config.name = "Bro::TCP";
		config.description = "TCP analyzer";
		return config;
		}
} plugin;

}
}
