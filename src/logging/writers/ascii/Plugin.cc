// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Ascii.h"

namespace plugin {
namespace Bro_AsciiWriter {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::logging::Component("Ascii", ::logging::writer::Ascii::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::AsciiWriter";
		config.description = "ASCII log writer";
		return config;
		}
} plugin;

}
}
