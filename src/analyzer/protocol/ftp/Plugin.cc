// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "FTP.h"

namespace plugin {
namespace Bro_FTP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("FTP", ::analyzer::ftp::FTP_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("FTP_ADAT", 0));

		plugin::Configuration config;
		config.name = "Bro::FTP";
		config.description = "FTP analyzer";
		return config;
		}
} plugin;

}
}
