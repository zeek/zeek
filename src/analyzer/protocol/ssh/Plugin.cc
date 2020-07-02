// See the file  in the main distribution directory for copyright.

#include "SSH.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_SSH {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("SSH", ::analyzer::SSH::SSH_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SSH";
		config.description = "Secure Shell analyzer";
		return config;
		}
	} plugin;

}
}
