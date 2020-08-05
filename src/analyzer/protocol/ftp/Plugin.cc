// See the file  in the main distribution directory for copyright.

#include "FTP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_FTP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("FTP", ::analyzer::ftp::FTP_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("FTP_ADAT", nullptr));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FTP";
		config.description = "FTP analyzer";
		return config;
		}
} plugin;

}
}
