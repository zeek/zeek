#include "plugin/Plugin.h"
#include "file_analysis/Component.h"

#include "Hash.h"

namespace plugin { namespace Bro_FileHash {

class Plugin : public plugin::Plugin {
protected:
	void InitPreScript()
		{
		SetName("Bro::FileHash");
		SetVersion(-1);
		SetAPIVersion(BRO_PLUGIN_API_VERSION);
		SetDynamicPlugin(false);

		SetDescription("Hash file content");

		AddComponent(new ::file_analysis::Component("MD5",
		        ::file_analysis::MD5::Instantiate));
		AddComponent(new ::file_analysis::Component("SHA1",
		        ::file_analysis::SHA1::Instantiate));
		AddComponent(new ::file_analysis::Component("SHA256",
		        ::file_analysis::SHA256::Instantiate));

		extern std::list<std::pair<const char*, int> > __bif_events_init();
		AddBifInitFunction(&__bif_events_init);
		}
};

Plugin __plugin;

} }
