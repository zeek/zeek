#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

#include "Extract.h"

namespace plugin { namespace Bro_FileExtract {

class Plugin : public plugin::Plugin {
protected:
	void InitPreScript()
		{
		SetName("Bro::FileExtract");
		SetVersion(-1);
		SetAPIVersion(BRO_PLUGIN_API_VERSION);
		SetDynamicPlugin(false);

		SetDescription("Extract file content to local file system");

		AddComponent(new ::file_analysis::Component("EXTRACT",
		        ::file_analysis::Extract::Instantiate));

		extern std::list<std::pair<const char*, int> > __bif_events_init();
		AddBifInitFunction(&__bif_events_init);
		extern std::list<std::pair<const char*, int> > __bif_functions_init();
		AddBifInitFunction(&__bif_functions_init);
		}
};

Plugin __plugin;

} }
