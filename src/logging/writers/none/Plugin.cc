// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "None.h"

namespace plugin {
namespace Bro_NoneWriter {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::logging::Component("None", ::logging::writer::None::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::NoneWriter";
		config.description = "None log writer (primarily for debugging)";
		return config;
		}
} plugin;

}
}
