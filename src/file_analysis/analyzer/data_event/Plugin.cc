// See the file in the main distribution directory for copyright.

#include "DataEvent.h"
#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

namespace zeek::plugin::detail::Zeek_FileDataEvent {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::file_analysis::Component("DATA_EVENT", zeek::file_analysis::detail::DataEvent::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileDataEvent";
		config.description = "Delivers file content";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_FileDataEvent
