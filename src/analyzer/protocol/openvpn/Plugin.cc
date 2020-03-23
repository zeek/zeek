// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"
#include "analyzer/Component.h"

#include "OpenVPN.h"

namespace plugin {
namespace Zeek_OpenVPN {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("OpenVPN", ::analyzer::openvpn::OpenVPN_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::OpenVPN";
		config.description = "OpenVPN analyzer";
		return config;
		}
} plugin;

}
}

