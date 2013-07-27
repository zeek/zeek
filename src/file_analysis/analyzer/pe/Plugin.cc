#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

#include "PE.h"

namespace plugin { namespace Bro_PE {

class Plugin : public plugin::Plugin {
protected:
	void InitPreScript()
		{
		SetName("Bro::PE");
		SetVersion(-1);
		SetAPIVersion(BRO_PLUGIN_API_VERSION);
		SetDynamicPlugin(false);

		SetDescription("Portable Executable analyzer");

		AddComponent(new ::file_analysis::Component("PE",
		        ::file_analysis::PE::Instantiate));

		extern std::list<std::pair<const char*, int> > __bif_events_init();
		AddBifInitFunction(&__bif_events_init);
		}
};

Plugin __plugin;

} }
