// See the file  in the main distribution directory for copyright.

#include "Login.h"
#include "Telnet.h"
#include "RSH.h"
#include "Rlogin.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_Login {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("Telnet", ::analyzer::login::Telnet_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Rsh", ::analyzer::login::Rsh_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("Rlogin", ::analyzer::login::Rlogin_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("NVT", 0));
		AddComponent(new ::analyzer::Component("Login", 0));
		AddComponent(new ::analyzer::Component("Contents_Rsh", 0));
		AddComponent(new ::analyzer::Component("Contents_Rlogin", 0));

		plugin::Configuration config;
		config.name = "Zeek::Login";
		config.description = "Telnet/Rsh/Rlogin analyzers";
		return config;
		}
} plugin;

}
}
