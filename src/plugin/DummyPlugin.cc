
#include "Plugin.h"

class DummyPlugin {
public:
	virtual void Init()
		{
		plugin::Description desc;
		desc.name = "Dummy";
		desc.description = "My little dummy plugin";
		desc.version = 2;
		desc.url = "http://dummy.bro.org";
		SetDescription(desc);

		analyzer::PluginComponent dummy("DUMMY", "Analyzer::DUMMY", dummy::Instantiate, dummy::Available, 0, false);
		AddComponent(dummy);
		}

Plugin* bro_plugin()
	{
	return new DummyPlugin();
	}






