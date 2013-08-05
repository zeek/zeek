#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

#include "Entropy.h"

namespace plugin { namespace Bro_FileEntropy {

class Plugin : public plugin::Plugin {
protected:
	void InitPreScript()
		{
		SetName("Bro::FileEntropy");
		SetVersion(-1);
		SetAPIVersion(BRO_PLUGIN_API_VERSION);
		SetDynamicPlugin(false);

		SetDescription("Entropy test file content");

		AddComponent(new ::file_analysis::Component("ENTROPY",
		        ::file_analysis::Entropy::Instantiate));

		extern std::list<std::pair<const char*, int> > __bif_events_init();
		AddBifInitFunction(&__bif_events_init);
		}
};

Plugin __plugin;

} }
