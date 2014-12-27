// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "./File.h"

namespace plugin {
namespace Bro_File {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("FTP_Data", ::analyzer::file::FTP_Data::Instantiate));
		AddComponent(new ::analyzer::Component("IRC_Data", ::analyzer::file::IRC_Data::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::File";
		config.description = "Generic file analyzer";
		return config;
		}
} plugin;

}
}
