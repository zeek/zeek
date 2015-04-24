// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Binary.h"

namespace plugin {
namespace Bro_BinaryReader {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::input::Component("Binary", ::input::reader::Binary::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::BinaryReader";
		config.description = "Binary input reader";
		return config;
		}
} plugin;

}
}
