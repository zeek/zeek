// See the file "COPYING" in the main distribution directory for copyright.

#include <sstream>
#include <fstream>
#include <dirent.h>
#include <glob.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>

#include "Manager.h"

#include "../Reporter.h"
#include "../Func.h"
#include "../Event.h"

using namespace plugin;

Plugin* Manager::current_plugin = 0;
string Manager::current_dir;
string Manager::current_sopath;

Manager::Manager()
	{
	init = false;
	hooks = new hook_list*[NUM_HOOKS];

	for ( int i = 0; i < NUM_HOOKS; i++ )
		hooks[i] = 0;
	}

Manager::~Manager()
	{
	assert(! init);

	for ( int i = 0; i < NUM_HOOKS; i++ )
		delete hooks[i];

	delete [] hooks;
	}

void Manager::SearchDynamicPlugins(const std::string& dir)
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
			SearchDynamicPlugins(d);

		return;
		}

	if ( ! is_dir(dir) )
		{
		DBG_LOG(DBG_PLUGINS, "Not a valid plugin directory: %s", dir.c_str());
		return;
		}

	// Check if it's a plugin dirctory.

	const std::string magic = dir + "/__bro_plugin__";

	if ( is_file(magic) )
		{
		// It's a plugin, get it's name.
		std::ifstream in(magic.c_str());

		if ( in.fail() )
			reporter->FatalError("cannot open plugin magic file %s", magic.c_str());

		std::string name;
		std::getline(in, name);
		strstrip(name);

		if ( name.empty() )
			reporter->FatalError("empty plugin magic file %s", magic.c_str());

		// Record it, so that we can later activate it.

		dynamic_plugins.insert(std::make_pair(name, dir));

		DBG_LOG(DBG_PLUGINS, "Found plugin %s in %s", name.c_str(), dir.c_str());
		return;
		}

	// No plugin here, traverse subirectories.

	DIR* d = opendir(dir.c_str());

	if ( ! d )
		{
		DBG_LOG(DBG_PLUGINS, "Cannot open directory %s", dir.c_str());
		return;
		}

	bool found = false;

	struct dirent *dp;

	while ( (dp = readdir(d)) )
		{
		struct stat st;

		if ( strcmp(dp->d_name, "..") == 0
		     || strcmp(dp->d_name, ".") == 0 )
			continue;

		string path = dir + "/" + dp->d_name;

		if( stat(path.c_str(), &st) < 0 )
			{
			DBG_LOG(DBG_PLUGINS, "Cannot stat %s: %s", path.c_str(), strerror(errno));
			continue;
			}

		if ( st.st_mode & S_IFDIR )
			SearchDynamicPlugins(path);
		}
	}

bool Manager::ActivateDynamicPluginInternal(const std::string& name)
	{
	dynamic_plugin_map::iterator m = dynamic_plugins.find(name);

	if ( m == dynamic_plugins.end() )
		{
		reporter->Error("plugin %s is not available", name.c_str());
		return false;
		}

	std::string dir = m->second + "/";

	if ( dir.empty() )
		{
		// That's our marker that we have already activated this
		// plugin. Silently ignore the new request.
		return true;
		}

	DBG_LOG(DBG_PLUGINS, "Activating plugin %s", name.c_str());

	// Add the "scripts" and "bif" directories to BROPATH.
	std::string scripts = dir + "scripts";

	if ( is_dir(scripts) )
		{
		DBG_LOG(DBG_PLUGINS, "  Adding %s to BROPATH", scripts.c_str());
		add_to_bro_path(scripts);
		}

	// Load {bif,scripts}/__load__.bro automatically.

	string init = dir + "lib/bif/__load__.bro";

	if ( is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
		}

	init = dir + "scripts/__load__.bro";

	if ( is_file(init) )
		{
		DBG_LOG(DBG_PLUGINS, "  Loading %s", init.c_str());
		scripts_to_load.push_back(init);
		}

	// Load shared libraries.

	string dypattern = dir + "/lib/*." + HOST_ARCHITECTURE + DYNAMIC_PLUGIN_SUFFIX;

	DBG_LOG(DBG_PLUGINS, "  Searching for shared libraries %s", dypattern.c_str());

	glob_t gl;

	if ( glob(dypattern.c_str(), 0, 0, &gl) == 0 )
		{
		for ( size_t i = 0; i < gl.gl_pathc; i++ )
			{
			const char* path = gl.gl_pathv[i];

			current_plugin = 0;
			current_dir = dir;
			current_sopath = path;
			void* hdl = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);

			if ( ! hdl )
				{
				const char* err = dlerror();
				reporter->FatalError("cannot load plugin library %s: %s", path, err ? err : "<unknown error>");
				}

			if ( ! current_plugin )
				reporter->FatalError("load plugin library %s did not instantiate a plugin", path);

			// We execute the pre-script initialization here; this in
			// fact could be *during* script initialization if we got
			// triggered via @load-plugin.
			current_plugin->InitPreScript();

			// Make sure the name the plugin reports is consistent with
			// what we expect from its magic file.
			if ( string(current_plugin->Name()) != name )
				reporter->FatalError("inconsistent plugin name: %s vs %s",
						     current_plugin->Name().c_str(), name.c_str());

			current_dir.clear();
			current_sopath.clear();
			current_plugin = 0;

			DBG_LOG(DBG_PLUGINS, "  Loaded %s", path);
			}
		}

	else
		{
		DBG_LOG(DBG_PLUGINS, "  No shared library found");
		}

	// Mark this plugin as activated by clearing the path.
	m->second.clear();

	return true;
	}

bool Manager::ActivateDynamicPlugin(const std::string& name)
	{
	if ( ! ActivateDynamicPluginInternal(name) )
		return false;

	UpdateInputFiles();
	return true;
	}

bool Manager::ActivateAllDynamicPlugins()
	{
	for ( dynamic_plugin_map::const_iterator i = dynamic_plugins.begin();
	      i != dynamic_plugins.end(); i++ )
		{
		if ( ! ActivateDynamicPluginInternal(i->first) )
			return false;
		}

	UpdateInputFiles();

	return true;
	}

void Manager::UpdateInputFiles()
	{
	for ( file_list::const_reverse_iterator i = scripts_to_load.rbegin();
	      i != scripts_to_load.rend(); i++ )
		add_input_file_at_front((*i).c_str());
	}

static bool plugin_cmp(const Plugin* a, const Plugin* b)
	{
	return a->Name() < b->Name();
	}

bool Manager::RegisterPlugin(Plugin *plugin)
	{
	Manager::PluginsInternal()->push_back(plugin);

	if ( current_dir.size() && current_sopath.size() )
		// A dynamic plugin, record its location.
		plugin->SetPluginLocation(current_dir.c_str(), current_sopath.c_str());

	// Sort plugins by name to make sure we have a deterministic order.
	PluginsInternal()->sort(plugin_cmp);

	current_plugin = plugin;
	return true;
	}

void Manager::InitPreScript()
	{
	assert(! init);

	for ( plugin_list::iterator i = Manager::PluginsInternal()->begin(); i != Manager::PluginsInternal()->end(); i++ )
		{
		Plugin* plugin = *i;
		plugin->InitPreScript();
		}

	init = true;
	}

void Manager::InitBifs()
	{
	for ( plugin_list::iterator i = Manager::PluginsInternal()->begin(); i != Manager::PluginsInternal()->end(); i++ )
		(*i)->InitBifs();
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

static bool hook_cmp(std::pair<int, Plugin*> a, std::pair<int, Plugin*> b)
	{
	if ( a.first == b.first )
		return a.second->Name() < a.second->Name();

	// Reverse sort.
	return a.first > b.first;
	}

std::list<std::pair<HookType, int> > Manager::HooksEnabledForPlugin(const Plugin* plugin) const
	{
	std::list<std::pair<HookType, int> > enabled;

	for ( int i = 0; i < NUM_HOOKS; i++ )
		{
		hook_list* l = hooks[i];

		if ( ! l )
			continue;

		for ( hook_list::iterator j = l->begin(); j != l->end(); j++ )
			{
			if ( (*j).second == plugin )
				enabled.push_back(std::make_pair((HookType)i, (*j).first));
			}
		}

	return enabled;
	}

void Manager::EnableHook(HookType hook, Plugin* plugin, int prio)
	{
	if ( ! hooks[hook] )
		hooks[hook] = new hook_list;

	hooks[hook]->push_back(std::make_pair(prio, plugin));
	hooks[hook]->sort(hook_cmp);
	}

void Manager::DisableHook(HookType hook, Plugin* plugin)
	{
	hook_list* l = hooks[hook];

	if ( ! l )
		return;

	for ( hook_list::iterator i = l->begin(); i != l->end(); i++ )
		{
		if ( (*i).second == plugin )
			{
			l->erase(i);
			break;
			}
		}

	if ( l->empty() )
		{
		delete l;
		hooks[hook] = 0;
		}
	}

int Manager::HookLoadFile(const string& file)
	{
	hook_list* l = hooks[HOOK_LOAD_FILE];

	for ( hook_list::iterator i = l->begin(); l && i != l->end(); i++ )
		{
		Plugin* p = (*i).second;

		int rc = p->HookLoadFile(file);

		if ( rc >= 0 )
			return rc;
		}

	return -1;
	}

Val* Manager::HookCallFunction(const Func* func, val_list* args) const
	{
	hook_list* l = hooks[HOOK_CALL_FUNCTION];

	for ( hook_list::iterator i = l->begin(); l && i != l->end(); i++ )
		{
		Plugin* p = (*i).second;

		Val* v = p->HookCallFunction(func, args);

		if ( v )
			return v;
		}

	return 0;
	}

bool Manager::HookQueueEvent(Event* event) const
	{
	hook_list* l = hooks[HOOK_QUEUE_EVENT];

	for ( hook_list::iterator i = l->begin(); l && i != l->end(); i++ )
		{
		Plugin* p = (*i).second;

		if ( p->HookQueueEvent(event) )
			return true;
		}

	return false;
	}

void Manager::HookDrainEvents() const
	{
	hook_list* l = hooks[HOOK_DRAIN_EVENTS];

	for ( hook_list::iterator i = l->begin(); l && i != l->end(); i++ )
		{
		Plugin* p = (*i).second;
		p->HookDrainEvents();
		}
	}

void Manager::HookUpdateNetworkTime(double network_time) const
	{
	hook_list* l = hooks[HOOK_UPDATE_NETWORK_TIME];

	for ( hook_list::iterator i = l->begin(); l && i != l->end(); i++ )
		{
		Plugin* p = (*i).second;
		p->HookUpdateNetworkTime(network_time);
		}
	}
