#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

#include "DataEvent.h"

namespace plugin { namespace Bro_FileDataEvent {

class Plugin : public plugin::Plugin {
protected:
	void InitPreScript()
		{
		SetName("Bro::FileDataEvent");
		SetVersion(-1);
		SetAPIVersion(BRO_PLUGIN_API_VERSION);
		SetDynamicPlugin(false);

		SetDescription("Delivers file content via events");

		AddComponent(new ::file_analysis::Component("DATA_EVENT",
		        ::file_analysis::DataEvent::Instantiate));
		}
};

Plugin __plugin;

} }
