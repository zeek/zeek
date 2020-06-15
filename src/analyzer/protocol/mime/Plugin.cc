// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

namespace plugin {
namespace Zeek_MIME {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		zeek::plugin::Configuration config;
		config.name = "Zeek::MIME";
		config.description = "MIME parsing";
		return config;
		}
} plugin;

}
}
