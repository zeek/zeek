// See the file in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/file_analysis/Component.h"
#include "zeek/file_analysis/analyzer/data_event/DataEvent.h"

namespace zeek::plugin::detail::Zeek_FileDataEvent
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::file_analysis::Component(
			"DATA_EVENT", zeek::file_analysis::detail::DataEvent::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::FileDataEvent";
		config.description = "Delivers file content";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_FileDataEvent
