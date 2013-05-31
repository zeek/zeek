// See the file "COPYING" in the main distribution directory for copyright.

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
	Manager::PluginsInternal()->push_back(plugin);
	return true;
	}

void Manager::InitPreScript()
	{
	assert(! init);

	for ( plugin_list::iterator i = Manager::PluginsInternal()->begin(); i != Manager::PluginsInternal()->end(); i++ )
		(*i)->InitPreScript();

	init = true;
	}

void Manager::InitPostScript()
	{
	assert(init);

	for ( plugin_list::iterator i = Manager::PluginsInternal()->begin(); i != Manager::PluginsInternal()->end(); i++ )
		(*i)->InitPostScript();
	}

void Manager::FinishPlugins()
	{
	assert(init);

	for ( plugin_list::iterator i = Manager::PluginsInternal()->begin(); i != Manager::PluginsInternal()->end(); i++ )
		{
		(*i)->Done();
//		delete *i;
		}

	Manager::PluginsInternal()->clear();

	init = false;
	}

Manager::plugin_list Manager::Plugins() const
	{
	return *Manager::PluginsInternal();
	}

Manager::plugin_list* Manager::PluginsInternal()
	{
	static plugin_list* plugins = 0;

	if ( ! plugins )
		plugins = new plugin_list;

	return plugins;
	}
