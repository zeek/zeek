// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Hash.h"

namespace plugin {
namespace Bro_FileHash {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("MD5", ::file_analysis::MD5::Instantiate));
		AddComponent(new ::file_analysis::Component("SHA1", ::file_analysis::SHA1::Instantiate));
		AddComponent(new ::file_analysis::Component("SHA256", ::file_analysis::SHA256::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::FileHash";
		config.description = "Hash file content";
		return config;
		}
} plugin;

}
}
