// See the file  in the main distribution directory for copyright.

#include "File.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_File {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("FTP_Data", ::analyzer::file::FTP_Data::Instantiate));
		AddComponent(new zeek::analyzer::Component("IRC_Data", ::analyzer::file::IRC_Data::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::File";
		config.description = "Generic file analyzer";
		return config;
		}
} plugin;

}
}
