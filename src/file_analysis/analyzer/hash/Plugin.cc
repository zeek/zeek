// See the file  in the main distribution directory for copyright.

#include "Hash.h"
#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

namespace plugin {
namespace Zeek_FileHash {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new ::file_analysis::Component("MD5", ::file_analysis::MD5::Instantiate));
		AddComponent(new ::file_analysis::Component("SHA1", ::file_analysis::SHA1::Instantiate));
		AddComponent(new ::file_analysis::Component("SHA256", ::file_analysis::SHA256::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileHash";
		config.description = "Hash file content";
		return config;
		}
} plugin;

}
}
