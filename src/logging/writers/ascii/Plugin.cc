// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Ascii.h"

namespace plugin {
namespace Zeek_AsciiWriter {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::logging::Component("Ascii", ::logging::writer::Ascii::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::AsciiWriter";
		config.description = "ASCII log writer";
		return config;
		}
} plugin;

}
}
