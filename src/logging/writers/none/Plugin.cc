// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "None.h"

namespace plugin {
namespace Zeek_NoneWriter {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::logging::Component("None", ::logging::writer::None::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::NoneWriter";
		config.description = "None log writer (primarily for debugging)";
		return config;
		}
} plugin;

}
}
