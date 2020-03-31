// See the file  in the main distribution directory for copyright.

#include "FTP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_FTP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("FTP", ::analyzer::ftp::FTP_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("FTP_ADAT", 0));

		plugin::Configuration config;
		config.name = "Zeek::FTP";
		config.description = "FTP analyzer";
		return config;
		}
} plugin;

}
}
