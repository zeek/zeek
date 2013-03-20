
#include "Manager.h"

#include "../Reporter.h"

using namespace plugin;

Manager::Manager()
	{
	init = false;
	}

Manager::~Manager()
	{
	assert(! init);
	}

bool Manager::LoadPlugin(const std::string& path)
	{
	assert(! init);
	reporter->InternalError("plugin::Manager::LoadPlugin not yet implemented");
	return false;
	}

bool Manager::LoadPluginsFrom(const std::string& dir)
	{
	assert(! init);
	reporter->InternalError("plugin::Manager::LoadPluginsFrom not yet implemented");
	return false;
	}

bool Manager::RegisterPlugin(Plugin *plugin)
	{
	assert(! init);

	plugin::Description desc = plugin->GetDescription();

	if ( desc.version != plugin::API_BUILTIN )
		{
		if ( desc.api_version == API_ERROR )
			reporter->InternalError("API version of plugin %s not initialized", desc.name.c_str());

		if ( desc.api_version != API_VERSION )
			reporter->FatalError("API version mismatch for plugin %s: expected %d, but have %d",
						 desc.name.c_str(), API_VERSION, desc.version);
		}

	plugins.push_back(plugin);
	return true;
	}

void Manager::InitPlugins()
	{
	assert(! init);

	for ( plugin_list::iterator i = plugins.begin(); i != plugins.end(); i++ )
		(*i)->Init();

	init = true;
	}

void Manager::FinishPlugins()
	{
	assert(init);

	for ( plugin_list::iterator i = plugins.begin(); i != plugins.end(); i++ )
		{
		(*i)->Done();
		delete *i;
		}

	plugins.clear();

	init = false;
	}

Manager::plugin_list Manager::Plugins() const
	{
	return plugins;
}

