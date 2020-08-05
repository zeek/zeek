// See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "SMB.h"

namespace plugin {
namespace Zeek_SMB {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("SMB", ::analyzer::smb::SMB_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("Contents_SMB", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SMB";
		config.description = "SMB analyzer";
		return config;
		}
} plugin;

}
}
