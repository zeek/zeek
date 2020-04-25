// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Ascii.h"

namespace plugin {
namespace Zeek_AsciiReader {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::input::Component("Ascii", ::input::reader::Ascii::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::AsciiReader";
		config.description = "ASCII input reader";
		return config;
		}
} plugin;

}
}
