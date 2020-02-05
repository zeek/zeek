// See the file in the main distribution directory for copyright.

#include "DataEvent.h"
#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

namespace plugin {
namespace Zeek_FileDataEvent {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::file_analysis::Component("DATA_EVENT", ::file_analysis::DataEvent::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::FileDataEvent";
		config.description = "Delivers file content";
		return config;
		}
} plugin;

}
}
