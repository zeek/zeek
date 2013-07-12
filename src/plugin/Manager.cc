// See the file "COPYING" in the main distribution directory for copyright.

#include <sstream>
#include <dirent.h>
#include <glob.h>
#include <dlfcn.h>
#include <sys/stat.h>

#include "Manager.h"

#include "../Reporter.h"

using namespace plugin;

string Manager::current_dir;

Manager::Manager()
	{
	init = false;
	}

Manager::~Manager()
	{
	assert(! init);
	}

void Manager::LoadPluginsFrom(const string& dir)
	{
	assert(! init);

	if ( dir.empty() )
		return;

	if ( dir.find(":") != string::npos )
		{
		// Split at ":".
		std::stringstream s(dir);
		std::string d;

		while ( std::getline(s, d, ':') )
			LoadPluginsFrom(d);

		return;
		}

	if ( ! is_dir(dir) )
		{
		DBG_LOG(DBG_PLUGINS, "not a valid plugin directory: %s", dir.c_str());
		return;
		}

	int rc = LoadPlugin(dir);

	if ( rc >= 0 )
		return;

	DBG_LOG(DBG_PLUGINS, "searching directory %s recursively for plugins", dir.c_str());

	DIR* d = opendir(dir.c_str());

	if ( ! d )
		{
		DBG_LOG(DBG_PLUGINS, "cannot open directory %s", dir.c_str());
		return;
		}

	bool found = false;

	struct dirent *dp;

	while ( (dp = readdir(d)) )
		{
		struct stat st;

		if( stat(dp->d_name, &st) < 0 )
			{
			DBG_LOG(DBG_PLUGINS, "cannot stat %s/%s", dir.c_str(), dp->d_name);
			continue;
			}

		if ( st.st_mode & S_IFDIR )
			LoadPluginsFrom(dir + dp->d_name);
		}
	}

int Manager::LoadPlugin(const std::string& dir)
	{
	assert(! init);

	// Check if it's a plugin dirctory.
	if ( ! is_file(dir + "/__bro_plugin__") )
		return -1;

	DBG_LOG(DBG_PLUGINS, "loading plugin from %s", dir.c_str());

	// Add the "scripts" directory to BROPATH.
	string scripts = dir + "/scripts";

	if ( is_dir(scripts) )
		{
		DBG_LOG(DBG_PLUGINS, "  adding %s to BROPATH", scripts.c_str());
		add_to_bro_path(scripts);
		}

	// Load dylib/scripts/__load__.bro automatically.
	string dyinit = dir + "/dylib/scripts/__load__.bro";

	if ( is_file(dyinit) )
		{
		DBG_LOG(DBG_PLUGINS, "  adding %s for loading", dyinit.c_str());
		add_input_file(dyinit.c_str());
		}

	// Load scripts/__load__.bro automatically.
	string init = scripts + "/__load__.bro";

	if ( is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  adding %s for loading", init.c_str());
		add_input_file(init.c_str());
		}

	// Load shared libraries.

	string dypattern = dir + "/dylib/*." + HOST_ARCHITECTURE + SHARED_LIBRARY_SUFFIX;

	DBG_LOG(DBG_PLUGINS, "  searching for shared libraries %s", dypattern.c_str());

	glob_t gl;

	if ( glob(dypattern.c_str(), 0, 0, &gl) == 0 )
		{
		for ( size_t i = 0; i < gl.gl_pathc; i++ )
			{
			const char* path = gl.gl_pathv[i];

			current_dir = dir;
			void* hdl = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
			current_dir.clear();

			if ( ! hdl )
				{
				const char* err = dlerror();
				reporter->FatalError("cannot load plugin library %s: %s", path, err ? err : "<unknown error>");
				}

			DBG_LOG(DBG_PLUGINS, "  loaded %s", path);
			}
		}

	else
		{
		DBG_LOG(DBG_PLUGINS, "  no shared library found");
		return 1;
		}

	return 1;
	}

bool Manager::RegisterPlugin(Plugin *plugin)
	{
	Manager::PluginsInternal()->push_back(plugin);

	if ( current_dir.size() )
		plugin->SetPluginDirectory(current_dir.c_str());

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
