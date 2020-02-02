// See the file  in the main distribution directory for copyright.

#include "File.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_File {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("FTP_Data", ::analyzer::file::FTP_Data::Instantiate));
		AddComponent(new ::analyzer::Component("IRC_Data", ::analyzer::file::IRC_Data::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::File";
		config.description = "Generic file analyzer";
		return config;
		}
} plugin;

}
}
