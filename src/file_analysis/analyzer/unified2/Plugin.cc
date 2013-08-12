#include "plugin/Plugin.h"

#include "file_analysis/Component.h"

#include "Unified2.h"

namespace plugin { namespace Bro_Unified2 {

class Plugin : public plugin::Plugin {
protected:
	void InitPreScript()
		{
		SetName("Bro::Unified2");
		SetVersion(-1);
		SetAPIVersion(BRO_PLUGIN_API_VERSION);
		SetDynamicPlugin(false);

		SetDescription("Analyze Unified2 alert files.");

		AddComponent(new ::file_analysis::Component("UNIFIED2",
		        ::file_analysis::Unified2::Instantiate));

		extern std::list<std::pair<const char*, int> > __bif_events_init();
		AddBifInitFunction(&__bif_events_init);

		extern std::list<std::pair<const char*, int> > __bif_types_init();
		AddBifInitFunction(&__bif_types_init);
		}
};

Plugin __plugin;

} }
