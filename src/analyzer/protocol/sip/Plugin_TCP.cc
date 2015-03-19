//See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "SIP_TCP.h"

namespace plugin {
  namespace Bro_SIP_TCP {
    class Plugin : public plugin::Plugin {
    public:
      plugin::Configuration Configure()
      {
	AddComponent(new ::analyzer::Component("SIP_TCP", ::analyzer::sip_tcp::SIP_Analyzer::Instantiate));
	plugin::Configuration config;
	config.name = "Bro::SIP_TCP";
	config.description = "SIP analyzer (TCP)";
	return config;
      }
    } plugin;
  }
}
