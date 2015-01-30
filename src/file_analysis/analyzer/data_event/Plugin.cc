// See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "DataEvent.h"

namespace plugin {
namespace Bro_FileDataEvent {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("DATA_EVENT", ::file_analysis::DataEvent::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::FileDataEvent";
		config.description = "Delivers file content";
		return config;
		}
} plugin;

}
}
